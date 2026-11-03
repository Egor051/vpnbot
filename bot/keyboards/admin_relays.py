"""Keyboards of the relay panel. Every relay is addressed by its ``id``."""

from __future__ import annotations

from collections.abc import Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import Relay
from services.relay_management import RelayOverview


def relays_list_keyboard(overviews: Sequence[RelayOverview]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = [
        [
            InlineKeyboardButton(
                text=f"{'🟢' if overview.relay.enabled else '⏸'} {overview.relay.label} · {overview.relay.name}",
                callback_data=f"admin:relay:{overview.relay.id}",
            )
        ]
        for overview in overviews
    ]
    rows.append([InlineKeyboardButton(text=t("btn_relay_add"), callback_data="admin:relay:add")])
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_card_keyboard(relay: Relay, *, suggest_source_ip: str | None = None) -> InlineKeyboardMarkup:
    base = f"admin:relay:{relay.id}"
    rows: list[list[InlineKeyboardButton]] = []
    if suggest_source_ip:
        rows.append(
            [
                InlineKeyboardButton(
                    text=t("btn_relay_add_source_ip", ip=suggest_source_ip), callback_data=f"{base}:addsrc"
                )
            ]
        )
    rows.extend(
        [
            [
                InlineKeyboardButton(text=t("btn_relay_edit_host"), callback_data=f"{base}:edit:host"),
                InlineKeyboardButton(text=t("btn_relay_edit_src"), callback_data=f"{base}:edit:src"),
            ],
            [
                InlineKeyboardButton(text=t("btn_relay_edit_label"), callback_data=f"{base}:edit:label"),
                InlineKeyboardButton(text=t("btn_relay_edit_note"), callback_data=f"{base}:edit:note"),
            ],
            [
                InlineKeyboardButton(
                    text=t("btn_relay_disable") if relay.enabled else t("btn_relay_enable"),
                    callback_data=f"{base}:toggle:enabled",
                ),
                InlineKeyboardButton(
                    text=t("btn_relay_subs_off") if relay.in_subscriptions else t("btn_relay_subs_on"),
                    callback_data=f"{base}:toggle:subs",
                ),
            ],
            [InlineKeyboardButton(text=t("btn_relay_check"), callback_data=f"{base}:check")],
            [InlineKeyboardButton(text=t("btn_relay_delete"), callback_data=f"{base}:del")],
            [InlineKeyboardButton(text=t("btn_relays_back"), callback_data="admin:relays")],
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_cancel_keyboard(cancel_callback: str) -> InlineKeyboardMarkup:
    """A wizard step's only button: back to where the wizard started."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data=cancel_callback)]]
    )


def relay_source_step_keyboard(host_ip: str | None) -> InlineKeyboardMarkup:
    """«Добавить relay», source IPs: «как host» when the host is an IPv4 address."""
    rows: list[list[InlineKeyboardButton]] = []
    if host_ip:
        rows.append(
            [InlineKeyboardButton(text=t("btn_relay_src_as_host", host=host_ip), callback_data="admin:relay:add:srcashost")]
        )
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:relays")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_label_step_keyboard(default_free: bool) -> InlineKeyboardMarkup:
    """«Добавить relay», label: the default marker as a button while it is free."""
    rows: list[list[InlineKeyboardButton]] = []
    if default_free:
        rows.append(
            [InlineKeyboardButton(text=t("btn_relay_label_default"), callback_data="admin:relay:add:labeldefault")]
        )
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:relays")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def relay_add_confirm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_relay_create"), callback_data="admin:relay:add:confirm")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:relays")],
        ]
    )


def relay_delete_confirm_keyboard(relay_id: int) -> InlineKeyboardMarkup:
    """Delete a relay that has no keys: one confirmation."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_relay_delete_confirm"), callback_data=f"admin:relay:{relay_id}:del:yes")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:relay:{relay_id}")],
        ]
    )


def relay_delete_impact_keyboard(relay_id: int) -> InlineKeyboardMarkup:
    """Delete a relay that still has keys: with them, disable instead, or cancel."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=t("btn_relay_delete_with_keys"), callback_data=f"admin:relay:{relay_id}:del:keys"
                )
            ],
            [
                InlineKeyboardButton(
                    text=t("btn_relay_disable_instead"), callback_data=f"admin:relay:{relay_id}:del:disable"
                )
            ],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:relay:{relay_id}")],
        ]
    )
