"""Admin panel → «🛰 Управлять relay»: list, card, add wizard, edits, delete.

SUPERADMIN only — every handler checks it, and the service checks it again. A
relay is addressed by its ``id`` in callback data; a callback that names a relay
deleted in the meantime gets a short alert and the fresh list instead of an
error. Input is validated by the same functions the ``.env`` loader used
(through :mod:`services.relay_management`); a bad value is explained and the
same step is asked again.
"""

from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import AdminRelayStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.keyboards.admin_relays import (
    relay_add_confirm_keyboard,
    relay_cancel_keyboard,
    relay_card_keyboard,
    relay_delete_confirm_keyboard,
    relay_delete_impact_keyboard,
    relay_label_step_keyboard,
    relay_source_step_keyboard,
    relay_toggle_confirm_keyboard,
    relays_list_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.totp_gate import require_totp
from bot.relays import relay_card_text, relay_delete_impact_text, relay_draft_text, relays_list_text
from config.validators import DEFAULT_RELAY_LABEL, format_ipv4_networks, ipv4_address
from i18n import t
from services.errors import InvalidOperation, NotFound
from services.relay_management import (
    RelayDeletionReport,
    RelayUpdateResult,
    parse_relay_host,
    parse_relay_source_ips,
)
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)

_EDIT_STATES = {
    "host": AdminRelayStates.edit_host,
    "src": AdminRelayStates.edit_source_ips,
    "label": AdminRelayStates.edit_label,
    "note": AdminRelayStates.edit_note,
}


def _relay_id(data: str) -> int:
    """The id in ``admin:relay:<id>[:…]`` (the regexps below guarantee the shape)."""
    return int(data.split(":")[2])


async def _leave_relay_wizard(state: FSMContext) -> None:
    """Navigating to the list or a card abandons any relay wizard in progress."""
    current = await state.get_state()
    if current is not None and current in AdminRelayStates.__all_states_names__:
        await state.clear()


# ── rendering ─────────────────────────────────────────────────────────────────


async def _list_screen(services: Services, actor_user_id: int, notice: str | None = None) -> tuple[str, Any]:
    overviews = await services.relays.list_overview(actor_user_id)
    probes = {overview.relay.id: services.relay_health.last_probe(overview.relay.id) for overview in overviews}
    text = relays_list_text(overviews, probes)
    if notice:
        text = f"{notice}\n\n{text}"
    return text, relays_list_keyboard(overviews)


async def _card_screen(
    services: Services,
    actor_user_id: int,
    relay_id: int,
    notice: str | None = None,
    *,
    suggest_source_ip: str | None = None,
) -> tuple[str, Any]:
    relay, usage = await services.relays.usage(actor_user_id, relay_id)
    text = relay_card_text(
        relay, active_keys=usage.active_keys, probe=services.relay_health.last_probe(relay.id)
    )
    if notice:
        text = f"{notice}\n\n{text}"
    return text, relay_card_keyboard(relay, suggest_source_ip=suggest_source_ip)


async def _show_list(callback: CallbackQuery, services: Services, notice: str | None = None) -> None:
    assert callback.message is not None and callback.from_user is not None
    text, markup = await _list_screen(services, callback.from_user.id, notice)
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


async def _show_card(
    callback: CallbackQuery,
    services: Services,
    relay_id: int,
    notice: str | None = None,
    *,
    suggest_source_ip: str | None = None,
) -> None:
    assert callback.message is not None and callback.from_user is not None
    text, markup = await _card_screen(
        services, callback.from_user.id, relay_id, notice, suggest_source_ip=suggest_source_ip
    )
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


async def _relay_gone(callback: CallbackQuery, services: Services, state: FSMContext | None = None) -> None:
    """A callback about a relay that no longer exists: say so, show the fresh list."""
    if state is not None:
        await _leave_relay_wizard(state)
    await safe_callback_answer(callback, t("err_relay_not_found"), show_alert=True)
    await _show_list(callback, services)


def _update_notice(result: RelayUpdateResult) -> str:
    """What to tell the admin after an edit."""
    if not result.changed:
        return t("relay_unchanged")
    lines = [t("relay_saved")]
    if result.single_keys_to_reimport is not None:
        lines = [t("relay_host_changed", host=code(result.relay.host), count=result.single_keys_to_reimport)]
    if result.suggest_source_ip:
        lines.append(t("relay_suggest_source_ip", ip=code(result.suggest_source_ip)))
    return "\n\n".join(lines)


def _deletion_notice(report: RelayDeletionReport) -> str:
    label = h(report.relay.label)
    if report.deleted:
        return t("relay_deleted", label=label, count=len(report.deleted_key_ids))
    if report.failed_key_id is not None:
        error = service_error_text(report.failure) if report.failure is not None else t("internal_error")
        return t(
            "relay_delete_failed",
            label=label,
            deleted=len(report.deleted_key_ids),
            remaining=report.remaining_keys,
            key_id=report.failed_key_id,
            error=h(error),
        )
    return t("relay_delete_blocked", label=label, remaining=report.remaining_keys)


# ── list and card ─────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:relays")
async def relays_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await _leave_relay_wizard(state)
        await safe_callback_answer(callback)
        await _show_list(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:relay:\d+$"))
async def relay_card(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await _leave_relay_wizard(state)
        relay_id = _relay_id(callback.data)
        try:
            text, markup = await _card_screen(services, callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── toggles, probe ────────────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:toggle:(enabled|subs)(:ok)?$"))
async def relay_toggle(callback: CallbackQuery, services: Services) -> None:
    """Switch a relay on/off, or in/out of subscriptions.

    Switching it OFF (or OUT) while keys ride it takes their links away, so that
    direction asks first (``…:ok`` runs it). Switching on, or a relay without
    keys, acts at once as before.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        parts = callback.data.split(":")
        field = parts[4]
        confirmed = len(parts) == 6
        try:
            relay, usage = await services.relays.usage(callback.from_user.id, relay_id)
            turning_off = relay.enabled if field == "enabled" else relay.in_subscriptions
            if turning_off and usage.active_keys > 0 and not confirmed:
                await safe_callback_answer(callback)
                await safe_edit_message_text(
                    callback.message,
                    t(f"relay_toggle_{field}_confirm", label=h(relay.label), count=usage.active_keys),
                    reply_markup=relay_toggle_confirm_keyboard(relay_id, field),
                )
                return
            if field == "enabled":
                result = await services.relays.update(callback.from_user.id, relay_id, enabled=not relay.enabled)
            else:
                result = await services.relays.update(
                    callback.from_user.id, relay_id, in_subscriptions=not relay.in_subscriptions
                )
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback, t("relay_saved_short"))
        notice = _update_notice(result)
        # A relay added to subscriptions reaches the subscriptions already issued
        # only through «All-in-One → Дополнить»: say so, it is in another section.
        if field == "subs" and result.relay.in_subscriptions and getattr(getattr(services, "settings", None), "subscription_enabled", False):
            notice = f"{notice}\n\n{t('relay_subs_topup_hint')}"
        await _show_card(callback, services, relay_id, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:check$"))
async def relay_check_now(callback: CallbackQuery, services: Services) -> None:
    """«Проверить сейчас»: the health loop's probe, once, with its result on the card."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback, t("relay_check_running"))
        probe = await services.relay_health.probe_now(relay)
        key = "relay_check_ok" if probe.ok else "relay_check_fail"
        notice = t(key, host=code(f"{probe.host}:{services.relay_health.port}"))
        try:
            await _show_card(callback, services, relay_id, notice)
        except NotFound:
            await _show_list(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:addsrc$"))
async def relay_add_host_to_sources(callback: CallbackQuery, services: Services) -> None:
    """After a host change: add the relay's (IPv4) host to its source IPs."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
            if ipv4_address(relay.host) is None:
                await safe_callback_answer(callback, t("action_stale"), show_alert=True)
                await _show_card(callback, services, relay_id)
                return
            result = await services.relays.add_source_ip(callback.from_user.id, relay_id, relay.host)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback, t("relay_saved_short"))
        await _show_card(callback, services, relay_id, _update_notice(result))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── delete ────────────────────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:del$"))
async def relay_delete_prompt(callback: CallbackQuery, services: Services) -> None:
    """No keys: one confirmation. Keys: delete them too / disable instead / cancel."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        try:
            relay, usage = await services.relays.usage(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback)
        if usage.keys == 0:
            await safe_edit_message_text(
                callback.message,
                t("relay_delete_confirm", label=h(relay.label), name=code(relay.name)),
                reply_markup=relay_delete_confirm_keyboard(relay_id),
            )
            return
        await safe_edit_message_text(
            callback.message,
            relay_delete_impact_text(relay, usage),
            reply_markup=relay_delete_impact_keyboard(relay_id),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:del:(yes|keys|disable)$"))
async def relay_delete_execute(callback: CallbackQuery, services: Services, state: FSMContext | None = None) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        action = callback.data.rsplit(":", 1)[-1]
        actor = callback.from_user.id
        # Deleting the relay WITH its keys is a mass deletion: TOTP first when enabled.
        if action == "keys" and not await require_totp(callback, state, services, action="relay_delete_keys"):
            return
        try:
            if action == "disable":
                relay = await services.relays.get(actor, relay_id)
                await services.relays.update(actor, relay_id, enabled=False)
                await safe_callback_answer(callback, t("relay_saved_short"))
                await _show_card(callback, services, relay_id, t("relay_disabled_instead", label=h(relay.label)))
                return
            await safe_callback_answer(callback, t("relay_deleting"))
            report = await services.relays.delete(actor, relay_id, with_keys=action == "keys")
        except NotFound:
            await _relay_gone(callback, services)
            return
        if report.deleted:
            await _show_list(callback, services, _deletion_notice(report))
            return
        if action == "yes" and report.failed_key_id is None and not report.deleted_key_ids:
            # Keys appeared since the prompt (none were there then): show the
            # screen that offers to delete them too.
            _, usage = await services.relays.usage(actor, relay_id)
            await safe_edit_message_text(
                callback.message,
                relay_delete_impact_text(report.relay, usage),
                reply_markup=relay_delete_impact_keyboard(relay_id),
            )
            return
        await _show_card(callback, services, relay_id, _deletion_notice(report))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «Добавить relay»: name → host → source IPs → label → confirm ──────────────


@router.callback_query(F.data == "admin:relay:add")
async def relay_add_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback)
        await state.set_state(AdminRelayStates.add_name)
        await state.update_data(relay_draft={})
        await safe_edit_message_text(
            callback.message, t("relay_add_name_prompt"), reply_markup=relay_cancel_keyboard("admin:relays")
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _draft(state: FSMContext) -> dict[str, str]:
    data = await state.get_data()
    draft = data.get("relay_draft")
    return dict(draft) if isinstance(draft, dict) else {}


def _retry_text(exc: InvalidOperation) -> str:
    """The rejection with the rejected value HTML-escaped.

    The reply is HTML and the value is whatever the admin typed — a relay label
    may legitimately hold ``<`` or ``&`` — so an unescaped echo would make
    Telegram refuse the whole message.
    """
    if exc.key:
        return t(exc.key, **{name: h(value) for name, value in exc.params.items()})
    return h(service_error_text(exc))


async def _retry(message: Message, exc: Exception, cancel_callback: str) -> None:
    """A rejected value: explain it and ask for the same step again."""
    if not isinstance(exc, InvalidOperation):
        raise exc
    await message.answer(
        f"{_retry_text(exc)}\n{t('relay_try_again')}", reply_markup=relay_cancel_keyboard(cancel_callback)
    )


@router.message(AdminRelayStates.add_name)
async def relay_add_name(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        try:
            name = await services.relays.check_new_name(message.from_user.id, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:relays")
            return
        draft = await _draft(state)
        draft["name"] = name
        await state.update_data(relay_draft=draft)
        await state.set_state(AdminRelayStates.add_host)
        await message.answer(t("relay_add_host_prompt"), reply_markup=relay_cancel_keyboard("admin:relays"))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminRelayStates.add_host)
async def relay_add_host(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        try:
            host = parse_relay_host(message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:relays")
            return
        draft = await _draft(state)
        draft["host"] = host
        await state.update_data(relay_draft=draft)
        await state.set_state(AdminRelayStates.add_source_ips)
        host_ip = host if ipv4_address(host) is not None else None
        await message.answer(t("relay_add_src_prompt"), reply_markup=relay_source_step_keyboard(host_ip))
    except Exception as exc:
        await answer_message_error(message, exc)


async def _ask_label(answer: Any, state: FSMContext, services: Services, actor_user_id: int) -> None:
    await state.set_state(AdminRelayStates.add_label)
    default_free = await services.relays.label_free(actor_user_id, DEFAULT_RELAY_LABEL)
    await answer(t("relay_add_label_prompt"), reply_markup=relay_label_step_keyboard(default_free))


@router.message(AdminRelayStates.add_source_ips)
async def relay_add_source_ips(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        try:
            networks = parse_relay_source_ips(message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:relays")
            return
        draft = await _draft(state)
        draft["source_ips"] = format_ipv4_networks(networks)
        await state.update_data(relay_draft=draft)
        await _ask_label(message.answer, state, services, message.from_user.id)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(AdminRelayStates.add_source_ips, F.data == "admin:relay:add:srcashost")
async def relay_add_source_as_host(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        draft = await _draft(state)
        host = draft.get("host", "")
        if ipv4_address(host) is None:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
            return
        draft["source_ips"] = format_ipv4_networks(parse_relay_source_ips(host))
        await state.update_data(relay_draft=draft)
        await safe_callback_answer(callback)
        await _ask_label(callback.message.answer, state, services, callback.from_user.id)
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _confirm_draft(answer: Any, state: FSMContext, draft: dict[str, str]) -> None:
    await state.update_data(relay_draft=draft)
    await state.set_state(AdminRelayStates.add_confirm)
    await answer(
        relay_draft_text(
            name=draft.get("name", ""),
            host=draft.get("host", ""),
            source_ips=draft.get("source_ips", ""),
            label=draft.get("label", ""),
        ),
        reply_markup=relay_add_confirm_keyboard(),
    )


@router.message(AdminRelayStates.add_label)
async def relay_add_label(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        try:
            label = await services.relays.check_label(message.from_user.id, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:relays")
            return
        draft = await _draft(state)
        draft["label"] = label
        await _confirm_draft(message.answer, state, draft)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(AdminRelayStates.add_label, F.data == "admin:relay:add:labeldefault")
async def relay_add_label_default(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        label = await services.relays.check_label(callback.from_user.id, DEFAULT_RELAY_LABEL)
        draft = await _draft(state)
        draft["label"] = label
        await safe_callback_answer(callback)
        await _confirm_draft(callback.message.answer, state, draft)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(AdminRelayStates.add_confirm, F.data == "admin:relay:add:confirm")
async def relay_add_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        draft = await _draft(state)
        if not all(draft.get(field) for field in ("name", "host", "source_ips", "label")):
            await state.clear()
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
            await _show_list(callback, services)
            return
        relay = await services.relays.create(
            callback.from_user.id,
            name=draft["name"],
            host=draft["host"],
            source_ips=draft["source_ips"],
            label=draft["label"],
        )
        await state.clear()
        await safe_callback_answer(callback, t("relay_saved_short"))
        await _show_card(callback, services, relay.id, t("relay_created", label=h(relay.label)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── field edits: host / source IPs / label / note ─────────────────────────────


@router.callback_query(F.data.regexp(r"^admin:relay:\d+:edit:(host|src|label|note)$"))
async def relay_edit_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        relay_id = _relay_id(callback.data)
        field = callback.data.rsplit(":", 1)[-1]
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services, state)
            return
        current = {
            "host": relay.host,
            "src": format_ipv4_networks(relay.source_ips),
            "label": relay.label,
            "note": relay.note or t("none"),
        }[field]
        await safe_callback_answer(callback)
        await state.set_state(_EDIT_STATES[field])
        await state.update_data(relay_id=relay_id)
        await safe_edit_message_text(
            callback.message,
            t(f"relay_edit_{field}_prompt", label=h(relay.label), value=code(current)),
            reply_markup=relay_cancel_keyboard(f"admin:relay:{relay_id}"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _apply_edit(message: Message, state: FSMContext, services: Services, field: str) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        data = await state.get_data()
        raw_id = data.get("relay_id")
        if raw_id is None:
            await state.clear()
            await message.answer(t("action_stale_msg"))
            return
        relay_id = int(raw_id)
        value = message.text or ""
        actor = message.from_user.id
        try:
            if field == "host":
                result = await services.relays.update(actor, relay_id, host=value)
            elif field == "src":
                result = await services.relays.update(actor, relay_id, source_ips=value)
            elif field == "label":
                await services.relays.check_label(actor, value, exclude_relay_id=relay_id)
                result = await services.relays.update(actor, relay_id, label=value)
            else:
                result = await services.relays.update(actor, relay_id, note=value)
        except NotFound:
            await state.clear()
            text, markup = await _list_screen(services, actor, t("err_relay_not_found"))
            await message.answer(text, reply_markup=markup)
            return
        except InvalidOperation as exc:
            await _retry(message, exc, f"admin:relay:{relay_id}")
            return
        await state.clear()
        text, markup = await _card_screen(
            services, actor, relay_id, _update_notice(result), suggest_source_ip=result.suggest_source_ip
        )
        await message.answer(text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminRelayStates.edit_host)
async def relay_edit_host(message: Message, state: FSMContext, services: Services) -> None:
    await _apply_edit(message, state, services, "host")


@router.message(AdminRelayStates.edit_source_ips)
async def relay_edit_source_ips(message: Message, state: FSMContext, services: Services) -> None:
    await _apply_edit(message, state, services, "src")


@router.message(AdminRelayStates.edit_label)
async def relay_edit_label(message: Message, state: FSMContext, services: Services) -> None:
    await _apply_edit(message, state, services, "label")


@router.message(AdminRelayStates.edit_note)
async def relay_edit_note(message: Message, state: FSMContext, services: Services) -> None:
    await _apply_edit(message, state, services, "note")
