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
from services.fallback import Candidate, FallbackOverview, HubCandidate


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def name_tag(name: str) -> str:
    """The short, stable tag of a suggested name in callback data."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]


def fallback_keyboard(overview: FallbackOverview, configured: bool = True) -> InlineKeyboardMarkup:
    """The main screen. Set up: the switch, «Проверить», «⚙️ Настройки», back — and
    «🔁 Повторить» only while a switch did not reach every name (the button that fixes
    that state). Not set up: «⚙️ Настроить фолбэк» and back. No «Обновить»: the screen
    is drawn anew on every open and after every action."""
    rows: list[list[InlineKeyboardButton]] = []
    if not configured:
        rows.append(_row(t("btn_fb_setup"), "admin:fb:setup"))
        rows.append(_row(t("btn_relays_back"), "admin:relays"))
        return InlineKeyboardMarkup(inline_keyboard=rows)
    if overview.mode_on:
        rows.append(_row(t("btn_fb_off"), "admin:fb:off"))
    else:
        rows.append(_row(t("btn_fb_on"), "admin:fb:on"))
    if overview.state == "partial":
        rows.append(_row(t("btn_fb_repeat"), "admin:fb:retry"))
    rows.append(_row(t("btn_fb_preflight"), "admin:fb:pf"))
    rows.append(_row(t("btn_fb_settings"), "admin:fb:set"))
    rows.append(_row(t("btn_relays_back"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def settings_keyboard(overview: FallbackOverview, *, auto_on: bool) -> InlineKeyboardMarkup:
    """«⚙️ Настройки»: names, token, the two IPv4, direct links' host, fallback-url,
    «Автопереключение», the setup again."""
    rows = [
        [InlineKeyboardButton(text=t("btn_fb_names"), callback_data="admin:fb:names"),
         InlineKeyboardButton(text=t("btn_fb_token"), callback_data="admin:fb:token")],
        [InlineKeyboardButton(text=t("btn_fb_addr_main"), callback_data="admin:fb:addr:main"),
         InlineKeyboardButton(text=t("btn_fb_addr_hub"), callback_data="admin:fb:addr:hub")],
        _row(t("btn_fb_direct"), "admin:fb:direct"),
        _row(t("btn_fb_sub_on") if overview.sub_fallback_url else t("btn_fb_sub_off"), "admin:fb:subfb"),
        _row(t("btn_fb_auto_on") if auto_on else t("btn_fb_auto_off"), "admin:fb:auto"),
        _row(t("btn_fb_setup_again"), "admin:fb:setup"),
        _row(t("btn_fb_back"), "admin:fb"),
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def candidates_keyboard(
    candidates: Sequence[Candidate], unchecked: Sequence[str], *, ctx: str, confirm_text: str, confirm_data: str,
    skip_data: str | None = None,
) -> InlineKeyboardMarkup:
    """One toggle per candidate (☑️ checked by default), then the ONE confirmation."""
    rows = [
        _row(("⬜ " if name_tag(c.name) in unchecked else "☑️ ") + c.name, f"admin:fb:cand:{ctx}:{name_tag(c.name)}")
        for c in candidates
    ]
    if candidates:
        rows.append(_row(confirm_text, confirm_data))
    rows.append(_row(t("btn_fb_name_new"), "admin:fb:nnew"))
    if skip_data is not None:
        rows.append(_row(t("btn_fb_setup_skip"), skip_data))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def hub_choice_keyboard(candidates: Sequence[HubCandidate]) -> InlineKeyboardMarkup:
    rows = [
        _row(f"🛟 {c.relay.name}" + (f" · {c.country}" if c.country else " · ?"), f"admin:fb:setup:hub:{c.relay.id}")
        for c in candidates
    ]
    rows.append(_row(t("btn_wizard_relay"), "admin:relays"))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def setup_origin_keyboard(relay_id: int, suggestion: str | None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if suggestion:
        rows.append(_row(t("btn_fb_origin_use", name=suggestion), f"admin:fb:setup:origin:{relay_id}"))
    rows.append(_row(t("btn_fb_origin_other"), f"admin:fb:setup:origin:{relay_id}:type"))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


# What fixes a refusal of «Включить» (an i18n key of the refusal or of a failed
# preflight item) — C4: never a bare refusal.
_FIX: dict[str, tuple[str, str]] = {
    "fb_err_no_token": ("btn_fb_fix_token", "admin:fb:tok:set"),
    "fb_err_token_rejected": ("btn_fb_fix_token", "admin:fb:tok:set"),
    "fb_err_token_inactive": ("btn_fb_fix_token", "admin:fb:tok:set"),
    "fb_err_token_zone": ("btn_fb_fix_token", "admin:fb:tok:set"),
    "fb_pf_token": ("btn_fb_fix_token", "admin:fb:tok:set"),
    "fb_err_no_names": ("btn_fb_fix_names", "admin:fb:on"),
    "fb_pf_names": ("btn_fb_fix_names", "admin:fb:on"),
    "fb_pf_hub": ("btn_fb_fix_hub", "admin:fb:setup"),
    "fb_err_not_configured": ("btn_fb_setup", "admin:fb:setup"),
    "fb_pf_addresses": ("btn_fb_addr_main", "admin:fb:addr:main"),
    "fb_err_no_main_ipv4": ("btn_fb_addr_main", "admin:fb:addr:main"),
    "fb_pf_record_count": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_pf_record_proxied": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_pf_record_foreign": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_pf_record_error": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_err_record_count": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_err_record_foreign": ("btn_fb_fix_names_list", "admin:fb:names"),
    "fb_err_dns": ("btn_fb_fix_names_list", "admin:fb:names"),
}
# Refusals about the hub itself: its card.
_HUB_FIX = frozenset({"fb_pf_agent_failed", "fb_pf_agent", "fb_pf_forward", "fb_pf_reach", "fb_pf_loop", "fb_err_hub_loop"})


def fix_keyboard(keys: Sequence[str], *, hub_id: int | None) -> InlineKeyboardMarkup:
    """One button per distinct fix of *keys*, then «Проверить» and back to the screen."""
    rows: list[list[InlineKeyboardButton]] = []
    seen: set[str] = set()
    for key in keys:
        if key in _HUB_FIX and hub_id is not None:
            label, data = "btn_fb_fix_hub_card", f"admin:relay:{hub_id}"
        elif key in _FIX:
            label, data = _FIX[key]
        else:
            continue
        if data not in seen:
            seen.add(data)
            rows.append(_row(t(label), data))
    rows.append(_row(t("btn_fb_preflight"), "admin:fb:pf"))
    rows.append(_row(t("btn_fb_back"), "admin:fb"))
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
