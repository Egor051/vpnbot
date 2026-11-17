"""Keyboards of the ONE relay screen. A relay is addressed by its ``id``, a pairing
code by its ``id`` (``admin:rpair:<id>``)."""

from __future__ import annotations

from collections.abc import Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import Relay, RelayPairing
from services.relay_health import ProbeResult
from services.relays import RelayOverview, agent_uninstalled


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


# The relay card's «в подписках» actions as they appear in callback data:
# ``admin:relay:<id>:subs:<action>[:run]``.
SUBS_ADD = "add"
SUBS_REMOVE = "rm"
SUBS_ACTIONS: tuple[str, ...] = (SUBS_ADD, SUBS_REMOVE)


def relays_list_keyboard(
    overviews: Sequence[RelayOverview],
    probes: dict[int, ProbeResult | None] | None = None,
    pending: Sequence[RelayPairing] = (),
    *,
    main_basic_visible: bool | None = None,
    fallback: bool = False,
) -> InlineKeyboardMarkup:
    """The relay list. *main_basic_visible* (when known) adds the main server's
    «👁 в базовых» switch — the main server has no card of its own; *fallback* adds
    «🛟 Режим фолбэка» (bot/handlers/admin_fallback.py)."""
    from bot.relays import relay_icon

    probes = probes or {}
    rows: list[list[InlineKeyboardButton]] = []
    for overview in overviews:
        relay = overview.relay
        marker = "" if relay.agent is not None else " ⚠️"
        rows.append(
            _row(f"{relay_icon(relay, probes.get(relay.id))} {relay.label} · {relay.name}{marker}", f"admin:relay:{relay.id}")
        )
    for pairing in pending:
        rows.append(_row(f"⏳ {pairing.name}", f"admin:rpair:{pairing.id}"))
    if main_basic_visible is not None:
        rows.append(
            _row(
                t("btn_relays_main_basic_on") if main_basic_visible else t("btn_relays_main_basic_off"),
                "admin:relays:mainbasic",
            )
        )
    if fallback:
        rows.append(_row(t("btn_fb_open"), "admin:fb"))
    rows.append(_row(t("btn_relay_add"), "admin:relay:add"))
    rows.append(_row(t("btn_back"), "admin:grp:infra"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_card_keyboard(
    relay: Relay,
    *,
    suggest_source_ip: str | None = None,
    pending_attach: RelayPairing | None = None,
    fallback: bool = False,
) -> InlineKeyboardMarkup:
    base = f"admin:relay:{relay.id}"
    rows: list[list[InlineKeyboardButton]] = []
    if suggest_source_ip:
        rows.append(_row(t("btn_relay_add_source_ip", ip=suggest_source_ip), f"{base}:addsrc"))
    rows.extend(
        [
            [
                InlineKeyboardButton(text=t("btn_relay_edit_host"), callback_data=f"{base}:edit:host"),
                InlineKeyboardButton(text=t("btn_relay_edit_label"), callback_data=f"{base}:edit:label"),
            ],
            [
                InlineKeyboardButton(text=t("btn_relay_edit_src"), callback_data=f"{base}:edit:src"),
                InlineKeyboardButton(text=t("btn_relay_edit_note"), callback_data=f"{base}:edit:note"),
            ],
            [
                InlineKeyboardButton(
                    text=t("btn_relay_disable") if relay.enabled else t("btn_relay_enable"),
                    callback_data=f"{base}:toggle:enabled",
                ),
                InlineKeyboardButton(
                    text=t("btn_relay_subs_rm") if relay.in_subscriptions else t("btn_relay_subs_add"),
                    callback_data=f"{base}:subs:{SUBS_REMOVE if relay.in_subscriptions else SUBS_ADD}",
                ),
            ],
            _row(t("btn_relay_basic_on") if relay.basic_visible else t("btn_relay_basic_off"), f"{base}:basic"),
            _row(t("btn_relay_check"), f"{base}:check"),
        ]
    )
    agent = relay.agent
    if agent is None:
        if pending_attach is not None:
            rows.append(_row(t("btn_relay_attach_code"), f"admin:rpair:{pending_attach.id}"))
        else:
            rows.append(_row(t("btn_relay_attach"), f"{base}:ag:attach"))
    elif not agent_uninstalled(agent):
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_relay_agent_update"), callback_data=f"{base}:ag:up"),
                InlineKeyboardButton(text=t("btn_relay_agent_forward"), callback_data=f"{base}:ag:fw"),
            ]
        )
        rows.append(_row(t("btn_relay_detach"), f"{base}:ag:detach"))
        if fallback:
            # The hub role of the fallback mode (bot/handlers/admin_fallback.py).
            if relay.is_hub:
                rows.append(_row(t("btn_fb_unhub"), f"admin:fb:unhub:{relay.id}"))
            else:
                rows.append(_row(t("btn_fb_make_hub"), f"admin:fb:hub:{relay.id}"))
    else:
        rows.append(_row(t("btn_relay_detach"), f"{base}:ag:detach"))
    rows.append(_row(t("btn_relay_delete"), f"{base}:del"))
    rows.append(_row(t("btn_relays_back"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_cancel_keyboard(cancel_callback: str) -> InlineKeyboardMarkup:
    """A step's only button: back to where it started."""
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), cancel_callback)])


def relay_back_keyboard(relay_id: int | None = None) -> InlineKeyboardMarkup:
    rows = []
    if relay_id is not None:
        rows.append(_row(t("btn_relay_page"), f"admin:relay:{relay_id}"))
    rows.append(_row(t("btn_relays_back"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_subs_confirm_keyboard(relay_id: int, action: str) -> InlineKeyboardMarkup:
    """Run / cancel under the plan of «Добавить в подписки» / «Убрать из подписок»."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_subs_run"), f"admin:relay:{relay_id}:subs:{action}:run"),
            _row(t("btn_cancel"), f"admin:relay:{relay_id}"),
        ]
    )


def relay_subs_report_keyboard(relay_id: int, action: str, *, retry: bool) -> InlineKeyboardMarkup:
    """Under the final report of a run: run it again (it finishes what failed), the
    relay's page, the list."""
    rows: list[list[InlineKeyboardButton]] = []
    if retry:
        rows.append(_row(t("btn_relay_subs_retry"), f"admin:relay:{relay_id}:subs:{action}"))
    rows.append(_row(t("btn_relay_page"), f"admin:relay:{relay_id}"))
    rows.append(_row(t("btn_relays_back"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_toggle_confirm_keyboard(relay_id: int, field: str) -> InlineKeyboardMarkup:
    """Confirm switching a relay off while it carries keys."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_confirm"), f"admin:relay:{relay_id}:toggle:{field}:ok"),
            _row(t("btn_cancel"), f"admin:relay:{relay_id}"),
        ]
    )


def relay_delete_keyboard(relay: Relay, *, has_keys: bool) -> InlineKeyboardMarkup:
    """Delete: no keys — one confirmation; keys — with them, disable instead, or cancel."""
    base = f"admin:relay:{relay.id}"
    managed = relay.agent is not None and not agent_uninstalled(relay.agent)
    rows: list[list[InlineKeyboardButton]] = []
    if has_keys:
        rows.append(
            _row(t("btn_relay_delete_with_keys_uninstall" if managed else "btn_relay_delete_with_keys"), f"{base}:del:keys")
        )
        rows.append(_row(t("btn_relay_disable_instead"), f"{base}:del:disable"))
    else:
        rows.append(_row(t("btn_relay_delete_uninstall" if managed else "btn_relay_delete_confirm"), f"{base}:del:yes"))
    rows.append(_row(t("btn_cancel"), base))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_unreachable_keyboard(relay_id: int, *, with_keys: bool) -> InlineKeyboardMarkup:
    """The relay did not run ``uninstall``: delete only the record, or back."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_delete_record"), f"admin:relay:{relay_id}:del:rec:{int(with_keys)}"),
            _row(t("btn_relay_page"), f"admin:relay:{relay_id}"),
        ]
    )


def relay_detach_keyboard(relay: Relay) -> InlineKeyboardMarkup:
    base = f"admin:relay:{relay.id}"
    rows = [_row(t("btn_relay_detach_keep"), f"{base}:ag:detach:keep")]
    if relay.agent is not None and not agent_uninstalled(relay.agent):
        rows.append(_row(t("btn_relay_detach_uninstall"), f"{base}:ag:detach:uninst"))
    rows.append(_row(t("btn_cancel"), base))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def pairing_keyboard(pairing: RelayPairing) -> InlineKeyboardMarkup:
    back = f"admin:relay:{pairing.relay_id}" if pairing.kind == "attach" and pairing.relay_id else "admin:relays"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_connect"), f"admin:rpair:{pairing.id}:go"),
            _row(t("btn_relay_cancel_pairing"), f"admin:rpair:{pairing.id}:x"),
            _row(t("btn_relay_back_short"), back),
        ]
    )


def pairing_retry_keyboard(pairing_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_retry"), f"admin:rpair:{pairing_id}:go"),
            _row(t("btn_relays_back"), "admin:relays"),
        ]
    )


def add_name_keyboard(suggestion: str | None) -> InlineKeyboardMarkup:
    rows = [_row(t("btn_relay_use_name", name=suggestion), "admin:relay:add:nm")] if suggestion else []
    rows.append(_row(t("btn_cancel"), "admin:relays"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def add_ipv4_keyboard(host: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_keep_ipv4", host=host), "admin:relay:add:ipok"),
            _row(t("btn_cancel"), "admin:relays"),
        ]
    )


def target_keyboard(target: str | None, data: str, cancel: str) -> InlineKeyboardMarkup:
    rows = [_row(t("btn_relay_use_target", target=target), data)] if target else []
    rows.append(_row(t("btn_cancel"), cancel))
    return InlineKeyboardMarkup(inline_keyboard=rows)
