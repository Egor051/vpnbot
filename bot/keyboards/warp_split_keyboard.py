"""Inline keyboards for the WARP selective-split GUI.

Pure presentation: every button maps to a ``wsplit:*`` callback handled in
``bot/handlers/admin_warp_split_ui.py``, which performs all mutations through
``WarpSplitManager``. No privileged logic lives here.

callback_data budget (Telegram limit is 64 bytes):
  ``wsplit:delok:255.255.255.255/32`` → 31 bytes, well within the limit for IPv4.
"""
from __future__ import annotations

from math import ceil

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t

# Keep a page small enough that a full page of two-button rows never approaches
# the Telegram message/keyboard size limits.
SPLIT_PAGE_SIZE = 8


def split_total_pages(total: int) -> int:
    """Return the number of pages needed for *total* prefixes (>= 1)."""
    if total <= 0:
        return 1
    return ceil(total / SPLIT_PAGE_SIZE)


def split_clamp_page(page: int, total: int) -> int:
    """Clamp *page* into the valid range for *total* prefixes."""
    return max(0, min(page, split_total_pages(total) - 1))


def split_page_slice(entries: list[str], page: int) -> list[str]:
    """Return the prefixes visible on *page* (already clamped)."""
    page = split_clamp_page(page, len(entries))
    start = page * SPLIT_PAGE_SIZE
    return entries[start : start + SPLIT_PAGE_SIZE]


def warp_split_panel_keyboard(entries: list[str], page: int) -> InlineKeyboardMarkup:
    """Build the split-panel keyboard for *page* of the full *entries* list."""
    total = len(entries)
    page = split_clamp_page(page, total)
    total_pages = split_total_pages(total)

    rows: list[list[InlineKeyboardButton]] = []
    for cidr in split_page_slice(entries, page):
        rows.append(
            [
                InlineKeyboardButton(text=cidr, callback_data="noop"),
                InlineKeyboardButton(text="🗑", callback_data=f"wsplit:del:{cidr}"),
            ]
        )

    action_row = [InlineKeyboardButton(text="➕ Добавить", callback_data="wsplit:add")]
    if total > 0:
        action_row.append(InlineKeyboardButton(text="🔄 Применить", callback_data="wsplit:apply"))
    rows.append(action_row)

    if total_pages > 1:
        rows.append(
            [
                InlineKeyboardButton(text="◀", callback_data=f"wsplit:p:{page - 1}")
                if page > 0
                else InlineKeyboardButton(text="·", callback_data="noop"),
                InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"),
                InlineKeyboardButton(text="▶", callback_data=f"wsplit:p:{page + 1}")
                if page < total_pages - 1
                else InlineKeyboardButton(text="·", callback_data="noop"),
            ]
        )

    rows.append([InlineKeyboardButton(text="⬅ Назад в WARP", callback_data="admin:warp")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def warp_split_add_keyboard() -> InlineKeyboardMarkup:
    """Keyboard shown while waiting for CIDR input (cancel returns to the panel)."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="wsplit:p:0")]]
    )


def warp_split_del_confirm_keyboard(cidr: str) -> InlineKeyboardMarkup:
    """Confirm/cancel keyboard for deleting a single *cidr*."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ Да", callback_data=f"wsplit:delok:{cidr}"),
                InlineKeyboardButton(text="❌ Нет", callback_data="wsplit:p:0"),
            ]
        ]
    )
