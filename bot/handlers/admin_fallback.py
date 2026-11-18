"""Admin panel → «🛰 Relay» → «🛟 Режим фолбэка» (docs/relay.md «Режим фолбэка (hub)»).

The screen of the fallback mode: its state, the hub, the addresses, the DNS API
token, the failover set and the two settings (direct links' host, the
subscription's ``fallback-url``); «Включить» / «Выключить» / «Повторить» and a
preflight that changes nothing. The hub role is given from a relay's card
(``admin:fb:hub:<id>``) — this module owns those callbacks too, under its own
prefix, so the relay screen's catch-all never swallows them.

SUPERADMIN only — every handler checks it and the service checks it again. Every
change is a dangerous action behind the TOTP gate; a typed step checks the
elevation again before it acts. The DNS API token is typed into the chat: that
message is deleted the moment it is read, whatever it holds, and the token is
never echoed back (services/fallback.py, adapters/cloudflare_dns.py).
"""

from __future__ import annotations

import logging
from typing import cast

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fallback import fallback_text, names_text, preflight_text, report_text
from bot.fsm.states import AdminFallbackStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.keyboards.admin_fallback import (
    back_keyboard,
    cancel_keyboard,
    confirm_keyboard,
    fallback_keyboard,
    name_tag,
    names_keyboard,
    origin_keyboard,
    token_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.totp_gate import require_totp
from i18n import t
from services.errors import InvalidOperation, NotFound, ServiceError
from services.fallback import FallbackService
from services.relays import host_is_ipv4
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)

# Typed steps: state → (prompt key, what the service does with the text).
_ADDRESS_STATES = {"main": AdminFallbackStates.main_ipv4, "hub": AdminFallbackStates.hub_ipv4}


def _service(services: Services) -> FallbackService:
    fallback = getattr(services, "fallback", None)
    if fallback is None:
        raise ServiceError("режим фолбэка не подключён", key="fb_err_unavailable")
    return cast(FallbackService, fallback)


def _message(callback: CallbackQuery) -> Message:
    return cast(Message, callback.message)


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
    totp = getattr(services, "totp", None)
    if totp is None:
        return True
    return not await totp.is_enabled(user_id) or totp.is_elevated(user_id)


async def _screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    overview = await _service(services).overview(actor)
    return fallback_text(overview, notice), fallback_keyboard(overview)


async def _edit(callback: CallbackQuery, screen: tuple[str, InlineKeyboardMarkup]) -> None:
    text, markup = screen
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


async def _show(callback: CallbackQuery, services: Services, notice: str | None = None) -> None:
    assert callback.from_user is not None
    await _edit(callback, await _screen(services, callback.from_user.id, notice))


async def _leave(state: FSMContext) -> None:
    current = await state.get_state()
    if current is not None and current in AdminFallbackStates.__all_states_names__:
        await state.clear()


# ── the screen ────────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:fb")
async def fallback_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await _leave(state)
        await safe_callback_answer(callback)
        await _show(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:pf")
async def fallback_preflight(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await safe_callback_answer(callback, t("fb_checking"))
        preflight = await _service(services).preflight(callback.from_user.id)
        await safe_edit_message_text(callback.message, preflight_text(preflight), reply_markup=back_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:(on|off)$"))
async def fallback_confirm(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        action = callback.data.rsplit(":", 1)[1]
        overview = await _service(services).overview(callback.from_user.id)
        if action == "on":
            text = t(
                "fb_confirm_on", count=len(overview.names), hub=h(overview.hub.name if overview.hub else "—"),
                ip=code(overview.hub_ipv4 or "—"),
            )
        else:
            text = t("fb_confirm_off", count=len(overview.names), ip=code(overview.main_ipv4 or "—"))
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=confirm_keyboard(action))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:(on:ok|off:ok|retry)$"))
async def fallback_switch(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_switch"):
            return
        await safe_callback_answer(callback, t("fb_switching"))
        await safe_edit_message_text(callback.message, t("fb_switching"))
        fallback = _service(services)
        actor = callback.from_user.id
        try:
            if callback.data.endswith("on:ok"):
                report = await fallback.enable(actor)
            elif callback.data.endswith("off:ok"):
                report = await fallback.disable(actor)
            else:
                report = await fallback.repeat(actor)
            notice = report_text(report)
        except ServiceError as exc:
            notice = t("fb_switch_failed", error=h(service_error_text(exc)))
        await _show(callback, services, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:subfb")
async def fallback_sub_header(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        fallback = _service(services)
        overview = await fallback.overview(callback.from_user.id)
        on = await fallback.set_sub_fallback_url(callback.from_user.id, not overview.sub_fallback_url)
        await safe_callback_answer(callback)
        notice = t("fb_sub_header_switched_on") if on else t("fb_sub_header_switched_off")
        if on and overview.hub is not None and host_is_ipv4(overview.hub.host):
            notice += "\n" + t("fb_sub_header_ip_warning")
        await _show(callback, services, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── the failover set ──────────────────────────────────────────────────────────


async def _names_screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    fallback = _service(services)
    overview = await fallback.overview(actor)
    candidates = await fallback.candidates(actor)
    text = names_text(overview, candidates)
    if notice:
        text = f"{notice}\n\n{text}"
    return text, names_keyboard(overview, candidates)


@router.callback_query(F.data == "admin:fb:names")
async def fallback_names(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _leave(state)
        await safe_callback_answer(callback)
        await _edit(callback, await _names_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:nadd:[0-9a-f]{10}$"))
async def fallback_name_add_suggested(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        actor = callback.from_user.id
        fallback = _service(services)
        tag = callback.data.rsplit(":", 1)[1]
        match = [name for name in await fallback.candidates(actor) if name_tag(name) == tag]
        if not match:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        else:
            try:
                await fallback.add_name(actor, match[0])
                await safe_callback_answer(callback, t("fb_name_added"))
            except InvalidOperation as exc:
                await safe_callback_answer(callback, service_error_text(exc), show_alert=True)
        await _edit(callback, await _names_screen(services, actor))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:nrm:\d+$"))
async def fallback_name_remove(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        actor = callback.from_user.id
        try:
            removed = await _service(services).remove_name(actor, int(callback.data.rsplit(":", 1)[1]))
            await safe_callback_answer(callback, t("fb_name_removed", name=removed.name))
        except (InvalidOperation, NotFound) as exc:
            await safe_callback_answer(callback, service_error_text(exc), show_alert=True)
        await _edit(callback, await _names_screen(services, actor))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── typed steps ───────────────────────────────────────────────────────────────


async def _ask(
    callback: CallbackQuery, state: FSMContext, target: object, prompt: str,
    markup: InlineKeyboardMarkup | None = None, **data: object,
) -> None:
    await state.set_state(target)  # type: ignore[arg-type]
    if data:
        await state.update_data(dict(data))
    await safe_callback_answer(callback)
    await _message(callback).answer(prompt, reply_markup=markup or cancel_keyboard())


@router.callback_query(F.data == "admin:fb:nnew")
async def fallback_name_new(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        await _ask(callback, state, AdminFallbackStates.name, t("fb_ask_name"), cancel_keyboard("admin:fb:names"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:addr:(main|hub)$"))
async def fallback_address(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        which = callback.data.rsplit(":", 1)[1]
        await _ask(callback, state, _ADDRESS_STATES[which], t(f"fb_ask_{which}_ipv4"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:direct")
async def fallback_direct(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        await _ask(callback, state, AdminFallbackStates.direct_host, t("fb_ask_direct_host"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:token")
async def fallback_token(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _leave(state)
        overview = await _service(services).overview(callback.from_user.id)
        text = t("fb_token_screen", path=code(str(_service(services).token_file.path)))
        status = t("fb_token_set", fp=code(overview.token_fingerprint or "?")) if overview.token_set else t("fb_token_none")
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, f"{text}\n\n{status}", reply_markup=token_keyboard(overview.token_set))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:tok:set")
async def fallback_token_set(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_token"):
            return
        await _ask(callback, state, AdminFallbackStates.token, t("fb_ask_token"), cancel_keyboard("admin:fb:token"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:tok:del")
async def fallback_token_delete(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_token"):
            return
        removed = await _service(services).delete_token(callback.from_user.id)
        await safe_callback_answer(callback, t("fb_token_deleted") if removed else t("fb_token_none"))
        await _show(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _typed(message: Message, state: FSMContext, services: Services) -> int | None:
    """The common start of a typed step: guard, elevation still fresh. The actor, or None."""
    if not await _guard_message(message, services):
        return None
    assert message.from_user is not None
    if not await _still_elevated(services, message.from_user.id):
        await state.clear()
        await message.answer(t("relay_reauth"), reply_markup=back_keyboard())
        return None
    return message.from_user.id


async def _done(message: Message, state: FSMContext, services: Services, actor: int, notice: str) -> None:
    await state.clear()
    text, markup = await _screen(services, actor, notice)
    await message.answer(text, reply_markup=markup)


async def _retry(message: Message, exc: ServiceError, cancel: str = "admin:fb") -> None:
    await message.answer(f"{h(service_error_text(exc))}\n{t('relay_try_again')}", reply_markup=cancel_keyboard(cancel))


@router.message(AdminFallbackStates.token)
async def fallback_token_input(message: Message, state: FSMContext, services: Services) -> None:
    """The DNS API token: the message goes away FIRST, whatever it holds."""
    raw = message.text or ""
    try:
        await message.delete()
    except Exception:
        logger.warning("Fallback: the message with the DNS API token could not be deleted — delete it by hand")
        await message.answer(t("fb_token_delete_by_hand"))
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        try:
            status = await _service(services).set_token(actor, raw)
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:fb:token")
            return
        await _done(message, state, services, actor, t("fb_token_saved", status=h(status)))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.name)
async def fallback_name_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        try:
            await _service(services).add_name(actor, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:fb:names")
            return
        await state.clear()
        text, markup = await _names_screen(services, actor, t("fb_name_added"))
        await message.answer(text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.main_ipv4)
@router.message(AdminFallbackStates.hub_ipv4)
async def fallback_address_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        which = "main" if await state.get_state() == AdminFallbackStates.main_ipv4.state else "hub"
        try:
            await _service(services).set_address(actor, which, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc)
            return
        await _done(message, state, services, actor, t("relay_saved"))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.direct_host)
async def fallback_direct_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        try:
            host = await _service(services).set_direct_host(actor, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc)
            return
        notice = t("fb_direct_set", host=code(host)) if host else t("fb_direct_cleared")
        await _done(message, state, services, actor, notice)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── the hub role (buttons on a relay's card) ──────────────────────────────────


@router.callback_query(F.data.regexp(r"^admin:fb:hub:\d+$"))
async def fallback_hub_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        relay_id = int(callback.data.rsplit(":", 1)[1])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        suggestion = _service(services).suggest_origin()
        await _ask(
            callback, state, AdminFallbackStates.origin, t("fb_ask_origin", suggestion=code(suggestion or "origin.<зона>")),
            origin_keyboard(relay_id, suggestion), relay_id=relay_id,
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _assign(services: Services, actor: int, relay_id: int, origin: str) -> str:
    try:
        outcome = await _service(services).assign_hub(actor, relay_id, origin)
    except ServiceError as exc:
        return t("fb_hub_failed", error=h(service_error_text(exc)))
    return t(
        "fb_hub_assigned", name=h(outcome.relay.name), origin=code(outcome.origin), ip=code(outcome.main_ipv4),
        created=t("fb_hub_record_created") if outcome.created_record else t("fb_hub_record_checked"),
    )


@router.callback_query(F.data.regexp(r"^admin:fb:hub:\d+:sug$"))
async def fallback_hub_suggested(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = int(callback.data.split(":")[3])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        suggestion = _service(services).suggest_origin()
        if suggestion is None:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
            return
        await state.clear()
        await safe_callback_answer(callback, t("fb_hub_assigning"))
        await safe_edit_message_text(callback.message, t("fb_hub_assigning"))
        notice = await _assign(services, callback.from_user.id, relay_id, suggestion)
        await safe_edit_message_text(callback.message, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminFallbackStates.origin)
async def fallback_origin_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        relay_id = int((await state.get_data()).get("relay_id") or 0)
        await state.clear()
        progress = await message.answer(t("fb_hub_assigning"))
        notice = await _assign(services, actor, relay_id, message.text or "")
        await safe_edit_message_text(progress, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_message_error(message, exc)


def _hub_back(relay_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_relay_page"), callback_data=f"admin:relay:{relay_id}")],
        [InlineKeyboardButton(text=t("btn_fb_open"), callback_data="admin:fb")],
    ])


@router.callback_query(F.data.regexp(r"^admin:fb:unhub:\d+$"))
async def fallback_hub_clear(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = int(callback.data.rsplit(":", 1)[1])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        try:
            relay = await _service(services).clear_hub(callback.from_user.id, relay_id)
            notice = t("fb_hub_cleared", name=h(relay.name))
        except ServiceError as exc:
            notice = t("fb_hub_failed", error=h(service_error_text(exc)))
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:"))
async def stale_fallback_callback(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Anything else under ``admin:fb:`` (an old button): a short note and the screen."""
    try:
        if not await _guard(callback, services):
            return
        await _leave(state)
        await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        await _show(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)
