"""Inline keyboards for the WARP split-list «Источники» sub-panel.

Pure presentation, same contract as :mod:`bot.keyboards.warp_split_keyboard`:
every button maps to a ``wsplit:*`` callback handled in
``bot/handlers/admin_warp_split_sources.py``, and no privileged logic lives here.

callback_data budget (Telegram's limit is 64 bytes): the longest form is
``wsplit:srcrefok:<slug>``, 16 bytes of prefix plus a slug capped at 40 by
``warp.split_merge.validate_slug`` — 56 bytes worst case.
"""
from __future__ import annotations

from collections.abc import Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from warp.feed_state import SplitSource


def warp_split_sources_keyboard(
    sources: Sequence[SplitSource], *, has_migratable: bool = False
) -> InlineKeyboardMarkup:
    """One row per source (toggle + refresh + delete), then the global actions."""
    rows: list[list[InlineKeyboardButton]] = []
    for source in sources:
        toggle_text = (
            t("btn_warp_split_source_off") if source.enabled else t("btn_warp_split_source_on")
        )
        toggle_data = f"wsplit:src{'off' if source.enabled else 'on'}:{source.slug}"
        rows.append(
            [
                InlineKeyboardButton(text=source.slug, callback_data="noop"),
                InlineKeyboardButton(text=toggle_text, callback_data=toggle_data),
                InlineKeyboardButton(text="🔄", callback_data=f"wsplit:srcref:{source.slug}"),
                InlineKeyboardButton(text="🗑", callback_data=f"wsplit:srcdel:{source.slug}"),
            ]
        )

    actions = [InlineKeyboardButton(text=t("btn_warp_split_source_add"), callback_data="wsplit:srcadd")]
    if any(source.enabled for source in sources):
        actions.append(
            InlineKeyboardButton(
                text=t("btn_warp_split_source_refresh_all"), callback_data="wsplit:srcrefall"
            )
        )
    rows.append(actions)
    if has_migratable:
        # Only offered when it would actually do something — a button that
        # reports "nothing to move" every time trains the operator to ignore it.
        rows.append(
            [InlineKeyboardButton(text=t("btn_warp_split_migrate"), callback_data="wsplit:mig")]
        )
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="wsplit:p:0")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def warp_split_confirm_keyboard(yes_data: str) -> InlineKeyboardMarkup:
    """Generic Yes/No, where No always returns to the sources panel."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=t("btn_yes"), callback_data=yes_data),
                InlineKeyboardButton(text=t("btn_no"), callback_data="wsplit:src"),
            ]
        ]
    )


def warp_split_source_add_keyboard() -> InlineKeyboardMarkup:
    """Shown while waiting for the new-source description."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="wsplit:src")]]
    )
