"""Admin panel → «🛰 Relay» — the ONE relay screen (the wizard's «🛰 Relay» opens it too).

Every relay is listed here, whoever set it up; its page has the common actions
(on/off, «в подписках», rename = the label, the links' host, source IPs, note,
check, delete) and a block about how it is managed: its agent (status, update,
ports/target, disconnect) or — for a relay set up by hand — «🔗 Подключить агент
(ключи не меняются)». «Добавить relay» is the only way to create one: a name, the
public host for links and a pairing code (services/relays.py).

SUPERADMIN only — every handler checks it and the service checks it again. Every
change is a dangerous action: the TOTP gate (bot/totp_gate.py) asks first when the
superadmin has TOTP on, and a step that waits for typed input checks the elevation
again before it acts. A relay is addressed by its ``id`` in callback data, a code by
``admin:rpair:<id>``; a callback about something gone gets a short alert and the
fresh list. Buttons of the two former sections still sitting in the chat history
(``wrl:*`` of «Мастер → Relay», the old manual «Добавить relay» steps) lead to this
screen, never to an error.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import AdminRelayStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.keyboards.admin_relays import (
    add_ipv4_keyboard,
    add_name_keyboard,
    pairing_keyboard,
    pairing_retry_keyboard,
    relay_back_keyboard,
    relay_cancel_keyboard,
    relay_card_keyboard,
    relay_delete_keyboard,
    relay_detach_keyboard,
    relay_toggle_confirm_keyboard,
    relay_unreachable_keyboard,
    relays_list_keyboard,
    target_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.relays import outcome_text, pairing_text, relay_card_text, relay_delete_text, relays_list_text
from bot.totp_gate import require_totp
from config.validators import format_ipv4_networks, ipv4_address
from i18n import t
from models.dto import Relay, RelayPairing
from services.errors import AccessDenied, InvalidOperation, NotFound, ServiceError
from services.relay_health import LEVEL_ICONS
from services.relay_pairing import format_ports
from services.relays import (
    IssuedPairing,
    PairingCheckFailed,
    RelayDeletionReport,
    RelayUpdateResult,
    agent_uninstalled,
    host_is_ipv4,
    parse_relay_host,
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
_RELAY_ACTION = r"^admin:relay:\d+"


def _message(callback: CallbackQuery) -> Message:
    """The message a callback sits under (``_guard`` made sure there is one)."""
    return cast(Message, callback.message)


def _relay_id(data: str) -> int:
    """The id in ``admin:relay:<id>[:…]`` (the regexps below guarantee the shape)."""
    return int(data.split(":")[2])


def _pairing_id(data: str) -> int:
    """The id in ``admin:rpair:<id>[:…]``."""
    return int(data.split(":")[2])


async def _leave_relay_wizard(state: FSMContext | None) -> None:
    """Navigating to the list or a page abandons any relay step in progress."""
    if state is None:
        return
    current = await state.get_state()
    if current is not None and current in AdminRelayStates.__all_states_names__:
        await state.clear()


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


async def _guard_message(message: Message, services: Services) -> bool:
    if message.from_user is None:
        return False
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return False
    await require_superadmin(services, message.from_user.id)
    return True


async def _still_elevated(services: Services, user_id: int) -> bool:
    """A typed step of a dangerous action: TOTP (when on) must still be fresh."""
    totp = getattr(services, "totp", None)
    if totp is None:
        return True
    return not await totp.is_enabled(user_id) or totp.is_elevated(user_id)


def _reason(services: Services) -> Any:
    return getattr(services.relay_health, "reason", None)


# ── rendering ─────────────────────────────────────────────────────────────────


async def _list_screen(services: Services, actor_user_id: int, notice: str | None = None) -> tuple[str, Any]:
    overviews = await services.relays.list_overview(actor_user_id)
    pending = await services.relays.pending(actor_user_id)
    probes = {overview.relay.id: services.relay_health.last_probe(overview.relay.id) for overview in overviews}
    text = relays_list_text(overviews, probes, pending=pending, reason=_reason(services))
    if notice:
        text = f"{notice}\n\n{text}"
    return text, relays_list_keyboard(overviews, probes, pending)


async def _pending_attach(services: Services, actor_user_id: int, relay: Relay) -> RelayPairing | None:
    if relay.agent is not None:
        return None
    for pairing in await services.relays.pending(actor_user_id):
        if pairing.kind == "attach" and pairing.relay_id == relay.id:
            return pairing
    return None


async def _card_screen(
    services: Services,
    actor_user_id: int,
    relay_id: int,
    notice: str | None = None,
    *,
    suggest_source_ip: str | None = None,
) -> tuple[str, Any]:
    relay, usage = await services.relays.usage(actor_user_id, relay_id)
    pending = await _pending_attach(services, actor_user_id, relay)
    text = relay_card_text(
        relay,
        active_keys=usage.active_keys,
        probe=services.relay_health.last_probe(relay.id),
        reason=_reason(services),
        pending_attach=pending,
    )
    if notice:
        text = f"{notice}\n\n{text}"
    return text, relay_card_keyboard(relay, suggest_source_ip=suggest_source_ip, pending_attach=pending)


async def _edit(callback: CallbackQuery, text: str, markup: InlineKeyboardMarkup) -> None:
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


async def _show_list(callback: CallbackQuery, services: Services, notice: str | None = None) -> None:
    assert callback.from_user is not None
    await _edit(callback, *await _list_screen(services, callback.from_user.id, notice))


async def _show_card(
    callback: CallbackQuery,
    services: Services,
    relay_id: int,
    notice: str | None = None,
    *,
    suggest_source_ip: str | None = None,
) -> None:
    assert callback.from_user is not None
    try:
        screen = await _card_screen(
            services, callback.from_user.id, relay_id, notice, suggest_source_ip=suggest_source_ip
        )
    except NotFound:
        await _show_list(callback, services, t("err_relay_not_found"))
        return
    await _edit(callback, *screen)


async def _relay_gone(callback: CallbackQuery, services: Services, state: FSMContext | None = None) -> None:
    """A callback about a relay (or code) that no longer exists: say so, show the fresh list."""
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
        if host_is_ipv4(result.relay.host):
            lines.append(t("relay_host_ipv4_warning"))
    if result.suggest_source_ip:
        lines.append(t("relay_suggest_source_ip", ip=code(result.suggest_source_ip)))
    return "\n\n".join(lines)


def _deletion_notice(report: RelayDeletionReport) -> str:
    label = h(report.relay.label)
    if report.deleted:
        text = t("relay_deleted", label=label, count=len(report.deleted_key_ids))
        if report.relay.agent is not None and not report.uninstalled:
            text = f"{text}\n{t('relay_deleted_record_only')}"
        return text
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
    text = t("relay_delete_blocked", label=label, remaining=report.remaining_keys)
    if report.uninstalled:
        text = f"{text}\n{t('relay_delete_resume_hint')}"
    return text


def _agent_failure(exc: ServiceError) -> bool:
    """An agent call that did not go through (refused, SSH, timeout, key) — not a
    validation error, a missing relay or a busy one."""
    return not isinstance(exc, (NotFound, InvalidOperation, AccessDenied))


def _retry_text(exc: InvalidOperation) -> str:
    """The rejection with the rejected value HTML-escaped (the reply is HTML and the
    value is whatever the admin typed)."""
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


async def _reauth(message: Message, state: FSMContext, relay_id: int | None = None) -> None:
    await state.clear()
    await message.answer(t("relay_reauth"), reply_markup=relay_back_keyboard(relay_id))


# ── list and page ─────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:relays")
async def relays_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await _leave_relay_wizard(state)
        await safe_callback_answer(callback)
        await _show_list(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r"$"))
async def relay_card(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        await _leave_relay_wizard(state)
        try:
            screen = await _card_screen(services, callback.from_user.id, _relay_id(callback.data))
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback)
        await _edit(callback, *screen)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── toggles, check, source IP offer ───────────────────────────────────────────


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":toggle:(enabled|subs)(:ok)?$"))
async def relay_toggle(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Switch a relay on/off, or in/out of subscriptions.

    Switching it OFF (or OUT) while keys ride it takes their links away, so that
    direction asks first (``…:ok`` runs it).
    """
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        parts = callback.data.split(":")
        field = parts[4]
        confirmed = len(parts) == 6
        try:
            relay, usage = await services.relays.usage(callback.from_user.id, relay_id)
            turning_off = relay.enabled if field == "enabled" else relay.in_subscriptions
            if turning_off and usage.active_keys > 0 and not confirmed:
                await safe_callback_answer(callback)
                await _edit(
                    callback,
                    t(f"relay_toggle_{field}_confirm", label=h(relay.label), count=usage.active_keys),
                    relay_toggle_confirm_keyboard(relay_id, field),
                )
                return
            if not await require_totp(callback, state, services, action="relay_edit"):
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
        if field == "subs" and result.relay.in_subscriptions and getattr(
            getattr(services, "settings", None), "subscription_enabled", False
        ):
            notice = f"{notice}\n\n{t('relay_subs_topup_hint')}"
        await _show_card(callback, services, relay_id, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":check$"))
async def relay_check_now(callback: CallbackQuery, services: Services) -> None:
    """«Проверить сейчас»: one health pass (traffic + the agent), its verdict on the page."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback, t("relay_check_running"))
        probe = await services.relay_health.probe_now(relay)
        reason = _reason(services)
        notice = t(
            "relay_check_result",
            icon=LEVEL_ICONS.get(probe.level, "⚪️"),
            host=code(probe.host),
            reason=reason(probe) if reason is not None else "",
        )
        await _show_card(callback, services, relay_id, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":addsrc$"))
async def relay_add_host_to_sources(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """After a host change: add the relay's (IPv4) host to its source IPs."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
            if ipv4_address(relay.host) is None:
                await safe_callback_answer(callback, t("action_stale"), show_alert=True)
                await _show_card(callback, services, relay_id)
                return
            if not await require_totp(callback, state, services, action="relay_edit"):
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


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":del$"))
async def relay_delete_prompt(callback: CallbackQuery, services: Services) -> None:
    """No keys: one confirmation. Keys: delete them too / disable instead / cancel.
    A relay with an agent says that ``uninstall`` runs on the relay first."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay, usage = await services.relays.usage(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        await safe_callback_answer(callback)
        await _edit(callback, relay_delete_text(relay, usage), relay_delete_keyboard(relay, has_keys=usage.keys > 0))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":del:(yes|keys|disable|rec:[01])$"))
async def relay_delete_execute(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        parts = callback.data.split(":")
        action = parts[4]
        actor = callback.from_user.id
        try:
            relay = await services.relays.get(actor, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        managed = relay.agent is not None and not agent_uninstalled(relay.agent)
        with_keys = action == "keys" or (action == "rec" and parts[5] == "1")
        relay_side = action != "rec"
        # Each call names its action literally: DANGEROUS_ACTIONS is the inventory.
        if action == "disable":
            allowed = await require_totp(callback, state, services, action="relay_edit")
        elif with_keys:
            allowed = await require_totp(callback, state, services, action="relay_delete_keys")
        elif managed and relay_side:
            allowed = await require_totp(callback, state, services, action="relay_uninstall")
        else:
            allowed = await require_totp(callback, state, services, action="relay_delete")
        if not allowed:
            return
        try:
            if action == "disable":
                await services.relays.update(actor, relay_id, enabled=False)
                await safe_callback_answer(callback, t("relay_saved_short"))
                await _show_card(callback, services, relay_id, t("relay_disabled_instead", label=h(relay.label)))
                return
            await safe_callback_answer(callback, t("relay_deleting"))
            try:
                report = await services.relays.delete(actor, relay_id, with_keys=with_keys, relay_side=relay_side)
            except ServiceError as exc:
                if not relay_side or not _agent_failure(exc):
                    raise
                await _edit(
                    callback,
                    t("relay_unreachable", error=h(service_error_text(exc))),
                    relay_unreachable_keyboard(relay_id, with_keys=with_keys),
                )
                return
        except NotFound:
            await _relay_gone(callback, services)
            return
        if report.deleted:
            await _show_list(callback, services, _deletion_notice(report))
            return
        if action == "yes" and report.failed_key_id is None and not report.deleted_key_ids and report.remaining_keys:
            # Keys appeared since the prompt (none were there then): show the
            # screen that offers to delete them too.
            current, usage = await services.relays.usage(actor, relay_id)
            notice = _deletion_notice(report)
            await _edit(
                callback,
                f"{notice}\n\n{relay_delete_text(current, usage)}",
                relay_delete_keyboard(current, has_keys=usage.keys > 0),
            )
            return
        await _show_card(callback, services, relay_id, _deletion_notice(report))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── field edits: host / source IPs / label (rename) / note ────────────────────


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":edit:(host|src|label|note)$"))
async def relay_edit_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        field = callback.data.rsplit(":", 1)[-1]
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services, state)
            return
        if not await require_totp(callback, state, services, action="relay_edit"):
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
        await _edit(
            callback,
            t(f"relay_edit_{field}_prompt", label=h(relay.label), value=code(current), name=code(relay.name)),
            relay_cancel_keyboard(f"admin:relay:{relay_id}"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _apply_edit(message: Message, state: FSMContext, services: Services, field: str) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        data = await state.get_data()
        raw_id = data.get("relay_id")
        if raw_id is None:
            await state.clear()
            await message.answer(t("action_stale_msg"))
            return
        relay_id = int(raw_id)
        actor = message.from_user.id
        if not await _still_elevated(services, actor):
            await _reauth(message, state, relay_id)
            return
        value = message.text or ""
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


# ── «Добавить relay»: name → public host → the main server's name → the code ──


@router.callback_query(F.data == "admin:relay:add")
async def relay_add_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not services.relays.agents_available:
            await safe_callback_answer(callback, t("relay_agent_unavailable"), show_alert=True)
            return
        if not await require_totp(callback, state, services, action="relay_pair"):
            return
        suggestion = await services.relays.suggest_name(callback.from_user.id)
        await state.set_state(AdminRelayStates.add_name)
        await state.update_data(relay_draft={"suggestion": suggestion or ""})
        await safe_callback_answer(callback)
        await _edit(callback, t("relay_add_name_prompt"), add_name_keyboard(suggestion))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _draft(state: FSMContext) -> dict[str, str]:
    data = await state.get_data()
    draft = data.get("relay_draft")
    return {str(k): str(v) for k, v in draft.items()} if isinstance(draft, dict) else {}


async def _after_name(message: Message, state: FSMContext, services: Services, actor: int, raw: str, *, edit: bool) -> None:
    try:
        name = await services.relays.check_new_name(actor, raw)
    except InvalidOperation as exc:
        await _retry(message, exc, "admin:relays")
        return
    draft = await _draft(state)
    draft["name"] = name
    await state.update_data(relay_draft=draft)
    await state.set_state(AdminRelayStates.add_host)
    text, markup = t("relay_add_host_prompt", name=h(name)), relay_cancel_keyboard("admin:relays")
    if edit:
        await safe_edit_message_text(message, text, reply_markup=markup)
    else:
        await message.answer(text, reply_markup=markup)


@router.callback_query(AdminRelayStates.add_name, F.data == "admin:relay:add:nm")
async def relay_add_suggested_name(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        draft = await _draft(state)
        await safe_callback_answer(callback)
        await _after_name(_message(callback), state, services, callback.from_user.id, draft.get("suggestion", ""), edit=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminRelayStates.add_name)
async def relay_add_name(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        await _after_name(message, state, services, message.from_user.id, message.text or "", edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


async def _ask_target(message: Message, state: FSMContext, services: Services, *, edit: bool) -> None:
    await state.set_state(AdminRelayStates.add_target)
    draft = await _draft(state)
    target = services.relays.default_target()
    key = "relay_add_target_prompt" if target else "relay_add_target_prompt_none"
    text = t(key, name=h(draft.get("name", "")), host=code(draft.get("host", "")))
    markup = target_keyboard(target, "admin:relay:add:tg", "admin:relays")
    if edit:
        await safe_edit_message_text(message, text, reply_markup=markup)
    else:
        await message.answer(text, reply_markup=markup)


@router.message(AdminRelayStates.add_host)
@router.message(AdminRelayStates.add_host_ipv4)
async def relay_add_host(message: Message, state: FSMContext, services: Services) -> None:
    """The PUBLIC host for links. A DNS name goes on; an IPv4 address is allowed but
    warned about first (a burned IP has to be changed at every client)."""
    try:
        if not await _guard_message(message, services):
            return
        try:
            host = parse_relay_host(message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:relays")
            return
        draft = await _draft(state)
        draft["host"] = host
        await state.update_data(relay_draft=draft)
        if host_is_ipv4(host):
            await state.set_state(AdminRelayStates.add_host_ipv4)
            await message.answer(t("relay_add_host_ipv4", host=code(host)), reply_markup=add_ipv4_keyboard(host))
            return
        await _ask_target(message, state, services, edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(AdminRelayStates.add_host_ipv4, F.data == "admin:relay:add:ipok")
async def relay_add_keep_ipv4(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await safe_callback_answer(callback)
        await _ask_target(_message(callback), state, services, edit=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _show_pairing(message: Message, issued: IssuedPairing, relay: Relay | None, *, edit: bool) -> None:
    text, markup = pairing_text(issued, relay), pairing_keyboard(issued.pairing)
    if edit:
        await safe_edit_message_text(message, text, reply_markup=markup)
    else:
        await message.answer(text, reply_markup=markup)


async def _issue_new(message: Message, state: FSMContext, services: Services, actor: int, target: str, *, edit: bool) -> None:
    if not await _still_elevated(services, actor):
        await _reauth(message, state)
        return
    draft = await _draft(state)
    try:
        issued = await services.relays.issue_new(
            actor, name=draft.get("name", ""), host=draft.get("host", ""), target_host=target
        )
    except InvalidOperation as exc:
        await _retry(message, exc, "admin:relays")
        return
    await state.clear()
    await _show_pairing(message, issued, None, edit=edit)


@router.callback_query(AdminRelayStates.add_target, F.data == "admin:relay:add:tg")
async def relay_add_default_target(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await safe_callback_answer(callback)
        target = services.relays.default_target() or ""
        await _issue_new(_message(callback), state, services, callback.from_user.id, target, edit=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminRelayStates.add_target)
async def relay_add_target(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        await _issue_new(message, state, services, message.from_user.id, (message.text or "").strip(), edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── the agent of a relay ──────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":ag:attach$"))
async def relay_attach(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """«🔗 Подключить агент»: a code for THIS relay — no name asked, nothing about the
    relay or its keys changes."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services, state)
            return
        if relay.agent is not None:
            await safe_callback_answer(callback, t("relay_agent_already", name=relay.name), show_alert=True)
            await _show_card(callback, services, relay_id)
            return
        if not services.relays.agents_available:
            await safe_callback_answer(callback, t("relay_agent_unavailable"), show_alert=True)
            return
        if not await require_totp(callback, state, services, action="relay_pair"):
            return
        target = services.relays.default_target()
        await safe_callback_answer(callback)
        if target is None:
            await state.set_state(AdminRelayStates.attach_target)
            await state.update_data(relay_id=relay_id)
            await _edit(
                callback,
                t("relay_attach_target_prompt", label=h(relay.label)),
                relay_cancel_keyboard(f"admin:relay:{relay_id}"),
            )
            return
        await state.clear()
        issued = await services.relays.issue_attach(callback.from_user.id, relay_id, target_host=target)
        await _show_pairing(_message(callback), issued, relay, edit=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminRelayStates.attach_target)
async def relay_attach_target(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        relay_id = int((await state.get_data()).get("relay_id") or 0)
        if not await _still_elevated(services, message.from_user.id):
            await _reauth(message, state, relay_id)
            return
        try:
            issued = await services.relays.issue_attach(
                message.from_user.id, relay_id, target_host=(message.text or "").strip()
            )
        except InvalidOperation as exc:
            await _retry(message, exc, f"admin:relay:{relay_id}")
            return
        await state.clear()
        relay = await services.relays.get(message.from_user.id, relay_id)
        await _show_pairing(message, issued, relay, edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":ag:up$"))
async def relay_agent_update(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        if not await require_totp(callback, state, services, action="relay_update"):
            return
        await safe_callback_answer(callback, t("relay_agent_updating"))
        try:
            reply = await services.relays.update_agent(callback.from_user.id, relay_id)
            raw_update = reply.payload.get("update")
            update: dict[str, Any] = raw_update if isinstance(raw_update, dict) else {}
            notice = t(
                "relay_agent_updated", state=h(str(update.get("state", "?"))), message=h(str(update.get("message", "")))
            )
        except NotFound:
            await _show_card(callback, services, relay_id)
            return
        except ServiceError as exc:
            notice = t("relay_agent_update_failed", error=h(service_error_text(exc)))
        await _show_card(callback, services, relay_id, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":ag:fw$"))
async def relay_agent_forward(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services, state)
            return
        agent = relay.agent
        if agent is None or agent_uninstalled(agent):
            await safe_callback_answer(callback, t("relay_agent_not_managed"), show_alert=True)
            await _show_card(callback, services, relay_id)
            return
        if not await require_totp(callback, state, services, action="relay_apply"):
            return
        await state.set_state(AdminRelayStates.forward)
        await state.update_data(relay_id=relay_id)
        await safe_callback_answer(callback)
        await _message(callback).answer(
            t(
                "relay_agent_ask_forward",
                current=code(f"{agent.target_host} tcp={format_ports(agent.tcp_ports)} udp={format_ports(agent.udp_ports)}"),
            ),
            reply_markup=relay_cancel_keyboard(f"admin:relay:{relay_id}"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def parse_forward_input(text: str) -> tuple[str, str, str]:
    """``<target> tcp=443[,…] udp=443[,…]`` — the words in any order after the target."""
    words = (text or "").split()
    if not words or len(words) > 3:
        raise InvalidOperation("формат: <имя> tcp=443 udp=443", key="relay_agent_forward_format")
    target, tcp, udp = words[0], "", ""
    for word in words[1:]:
        key, _, value = word.partition("=")
        if key == "tcp" and not tcp:
            tcp = value
        elif key == "udp" and not udp:
            udp = value
        else:
            raise InvalidOperation("формат: <имя> tcp=443 udp=443", key="relay_agent_forward_format")
    return target, tcp, udp


@router.message(AdminRelayStates.forward)
async def relay_agent_forward_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        relay_id = int((await state.get_data()).get("relay_id") or 0)
        if not await _still_elevated(services, message.from_user.id):
            await _reauth(message, state, relay_id)
            return
        relay = await services.relays.get(message.from_user.id, relay_id)
        agent = relay.agent
        if agent is None:
            await state.clear()
            await message.answer(t("relay_agent_not_managed"), reply_markup=relay_back_keyboard(relay_id))
            return
        try:
            target, tcp, udp = parse_forward_input(message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, f"admin:relay:{relay_id}")
            return
        progress = await message.answer(t("relay_agent_applying"))
        try:
            await services.relays.change_forward(
                message.from_user.id, relay_id, target_host=target,
                tcp=tcp or format_ports(agent.tcp_ports), udp=udp or format_ports(agent.udp_ports),
            )
            notice = t("relay_agent_forward_done")
        except ServiceError as exc:
            notice = t("relay_agent_forward_failed", error=h(service_error_text(exc)))
        await state.clear()
        text, markup = await _card_screen(services, message.from_user.id, relay_id, notice)
        await safe_edit_message_text(progress, text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":ag:detach$"))
async def relay_detach_prompt(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        try:
            relay = await services.relays.get(callback.from_user.id, relay_id)
        except NotFound:
            await _relay_gone(callback, services)
            return
        if relay.agent is None:
            await safe_callback_answer(callback, t("relay_agent_not_managed"), show_alert=True)
            await _show_card(callback, services, relay_id)
            return
        await safe_callback_answer(callback)
        await _edit(callback, t("relay_detach_confirm", label=h(relay.label), name=code(relay.name)), relay_detach_keyboard(relay))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(_RELAY_ACTION + r":ag:detach:(keep|uninst)$"))
async def relay_detach_execute(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _relay_id(callback.data)
        uninstall = callback.data.endswith(":uninst")
        if uninstall:
            allowed = await require_totp(callback, state, services, action="relay_uninstall")
        else:
            allowed = await require_totp(callback, state, services, action="relay_detach")
        if not allowed:
            return
        await safe_callback_answer(callback, t("relay_detaching"))
        try:
            report = await services.relays.detach_agent(callback.from_user.id, relay_id, uninstall=uninstall)
        except NotFound:
            await _show_card(callback, services, relay_id)
            return
        except ServiceError as exc:
            if not uninstall or not _agent_failure(exc):
                raise
            await _show_card(callback, services, relay_id, t("relay_detach_uninstall_failed", error=h(service_error_text(exc))))
            return
        key = "relay_detached_uninstalled" if report.uninstalled else "relay_detached"
        await _show_card(callback, services, relay_id, t(key, label=h(report.relay.label)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── pairing codes: view, cancel, connect ──────────────────────────────────────


async def _pairing_relay(services: Services, actor: int, pairing: RelayPairing) -> Relay | None:
    if pairing.kind != "attach" or pairing.relay_id is None:
        return None
    try:
        return await services.relays.get(actor, pairing.relay_id)
    except NotFound:
        return None


async def _open_pairing(callback: CallbackQuery, services: Services, pairing_id: int) -> None:
    assert callback.from_user is not None
    try:
        issued = await services.relays.show(callback.from_user.id, pairing_id)
    except NotFound:
        await safe_callback_answer(callback, t("relay_pair_not_pending"), show_alert=True)
        await _show_list(callback, services)
        return
    await safe_callback_answer(callback)
    relay = await _pairing_relay(services, callback.from_user.id, issued.pairing)
    await _show_pairing(_message(callback), issued, relay, edit=True)


@router.callback_query(F.data.regexp(r"^admin:rpair:\d+$"))
async def relay_pairing_view(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        await _open_pairing(callback, services, _pairing_id(callback.data))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _cancel_pairing(callback: CallbackQuery, state: FSMContext, services: Services, pairing_id: int) -> None:
    assert callback.from_user is not None
    await _leave_relay_wizard(state)
    pairing = await services.relays.relays.get_pairing(pairing_id)
    await services.relays.cancel(callback.from_user.id, pairing_id)
    await safe_callback_answer(callback, t("relay_pairing_cancelled"))
    if pairing is not None and pairing.kind == "attach" and pairing.relay_id is not None:
        await _show_card(callback, services, pairing.relay_id)
        return
    await _show_list(callback, services)


@router.callback_query(F.data.regexp(r"^admin:rpair:\d+:x$"))
async def relay_pairing_cancel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        await _cancel_pairing(callback, state, services, _pairing_id(callback.data))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _start_connect(callback: CallbackQuery, state: FSMContext, services: Services, pairing_id: int) -> None:
    assert callback.from_user is not None
    try:
        await services.relays.show(callback.from_user.id, pairing_id)  # still pending?
    except NotFound:
        await safe_callback_answer(callback, t("relay_pair_not_pending"), show_alert=True)
        await _show_list(callback, services)
        return
    if not await require_totp(callback, state, services, action="relay_connect"):
        return
    await state.set_state(AdminRelayStates.pair_address)
    await state.update_data(relay_pairing=pairing_id)
    await safe_callback_answer(callback)
    await _message(callback).answer(t("relay_ask_address"), reply_markup=relay_cancel_keyboard("admin:relays"))


@router.callback_query(F.data.regexp(r"^admin:rpair:\d+:go$"))
async def relay_connect(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        await _start_connect(callback, state, services, _pairing_id(callback.data))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminRelayStates.pair_address)
async def relay_connect_address(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        pairing_id = int((await state.get_data()).get("relay_pairing") or 0)
        if not await _still_elevated(services, message.from_user.id):
            await _reauth(message, state)
            return
        progress = await message.answer(t("relay_connecting"))
        try:
            outcome = await services.relays.complete(message.from_user.id, pairing_id, message.text or "")
        except PairingCheckFailed as exc:
            await safe_edit_message_text(
                progress,
                t("relay_check_failed_pairing", checks=h(exc.checks.describe())),
                reply_markup=pairing_retry_keyboard(pairing_id),
            )
            return
        except ServiceError as exc:
            await safe_edit_message_text(
                progress,
                t("relay_connect_failed", error=h(service_error_text(exc))),
                reply_markup=pairing_retry_keyboard(pairing_id),
            )
            return
        await state.clear()
        await safe_edit_message_text(progress, outcome_text(outcome), reply_markup=relay_back_keyboard(outcome.relay.id))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── buttons of the two former sections still in the chat history ──────────────
#
# «Мастер настройки → Relay» (``wrl:*``) and the old manual «Добавить relay» steps
# of the panel lead to this screen: the relay's page, the code, or the list.


@router.callback_query(F.data.regexp(r"^wrl:"))
async def legacy_wizard_relay(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        parts = callback.data.split(":")
        kind = parts[1] if len(parts) > 1 else ""
        number = parts[2] if len(parts) > 2 and parts[2].isdigit() and 0 < int(parts[2]) < 10**9 else None
        await _leave_relay_wizard(state)
        if number is not None and kind in {"r", "st", "up", "fw", "del", "dk", "dr"}:
            await safe_callback_answer(callback)
            await _show_card(callback, services, int(number))
            return
        if number is not None and kind == "px":
            await _cancel_pairing(callback, state, services, int(number))
            return
        if number is not None and kind == "pc":
            await _start_connect(callback, state, services, int(number))
            return
        if number is not None and kind == "p":
            await _open_pairing(callback, services, int(number))
            return
        await safe_callback_answer(callback)
        await _show_list(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:(relay|rpair):"))
async def stale_relay_callback(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Anything else under the relay screen — the old manual add steps
    (``admin:relay:add:srcashost|labeldefault|confirm``) or a step button pressed
    outside its step: a short note and the list."""
    try:
        if not await _guard(callback, services):
            return
        await _leave_relay_wizard(state)
        await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        await _show_list(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)
