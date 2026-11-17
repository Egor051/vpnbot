"""Keyboards of the «🛟 Режим фолбэка» screens. Every callback starts with ``admin:fb``.

A name of the set is addressed by its ``id`` (``admin:fb:nrm:<id>``); a suggested
name by a short hash of it (``admin:fb:nadd:<hash>``) — a DNS name does not fit in
callback data, and the handler recomputes the suggestions and matches the hash.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from services.fallback import FallbackOverview


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def name_tag(name: str) -> str:
    """The short, stable tag of a suggested name in callback data."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]


def fallback_keyboard(overview: FallbackOverview) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if overview.state == "partial":
        rows.append(_row(t("btn_fb_repeat"), "admin:fb:retry"))
    if overview.mode_on:
        rows.append(_row(t("btn_fb_off"), "admin:fb:off"))
    else:
        rows.append(_row(t("btn_fb_on"), "admin:fb:on"))
    rows.append(_row(t("btn_fb_preflight"), "admin:fb:pf"))
    rows.append([
        InlineKeyboardButton(text=t("btn_fb_names"), callback_data="admin:fb:names"),
        InlineKeyboardButton(text=t("btn_fb_token"), callback_data="admin:fb:token"),
    ])
    rows.append([
        InlineKeyboardButton(text=t("btn_fb_addr_main"), callback_data="admin:fb:addr:main"),
        InlineKeyboardButton(text=t("btn_fb_addr_hub"), callback_data="admin:fb:addr:hub"),
    ])
    rows.append(_row(t("btn_fb_direct"), "admin:fb:direct"))
    rows.append(_row(t("btn_fb_sub_on") if overview.sub_fallback_url else t("btn_fb_sub_off"), "admin:fb:subfb"))
    rows.append(_row(t("btn_fb_refresh"), "admin:fb"))
    rows.append(_row(t("btn_relays_back"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_keyboard(action: str) -> InlineKeyboardMarkup:
    """«✅ Да» → ``admin:fb:<action>:ok``; «Отмена» → the screen."""
    return InlineKeyboardMarkup(inline_keyboard=[
        _row(t("btn_fb_confirm_on") if action == "on" else t("btn_fb_confirm_off"), f"admin:fb:{action}:ok"),
        _row(t("btn_cancel"), "admin:fb"),
    ])


def back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_fb_back"), "admin:fb")])


def cancel_keyboard(callback: str = "admin:fb") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), callback)])


def names_keyboard(overview: FallbackOverview, candidates: Sequence[str]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for name in overview.names:
        rows.append(_row(t("btn_fb_name_remove", name=name.name), f"admin:fb:nrm:{name.id}"))
    for candidate in candidates:
        rows.append(_row(t("btn_fb_name_add", name=candidate), f"admin:fb:nadd:{name_tag(candidate)}"))
    rows.append(_row(t("btn_fb_name_new"), "admin:fb:nnew"))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def token_keyboard(token_set: bool) -> InlineKeyboardMarkup:
    rows = [_row(t("btn_fb_token_set"), "admin:fb:tok:set")]
    if token_set:
        rows.append(_row(t("btn_fb_token_delete"), "admin:fb:tok:del"))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def origin_keyboard(relay_id: int, suggestion: str | None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if suggestion:
        rows.append(_row(t("btn_fb_origin_use", name=suggestion), f"admin:fb:hub:{relay_id}:sug"))
    rows.append(_row(t("btn_cancel"), f"admin:relay:{relay_id}"))
    return InlineKeyboardMarkup(inline_keyboard=rows)
