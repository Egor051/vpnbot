"""«🧭 Первичная настройка» (services/first_setup.py, docs/first-setup.md). SUPERADMIN only.

Offered by itself right after the claim when no protocol is on the host, and from
«🧙 Мастер настройки» at any time (an open setup is resumed where it stopped). The domain
and the Cloudflare token are typed into the chat — the token's message is deleted the
moment it is read, before anything else; «✅ Продолжить» under the protocols is the one
confirmation of everything that follows (TOTP when it is on).
"""

from __future__ import annotations

import logging

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import SetupStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.setup_views import setup_keyboard, setup_text
from bot.totp_gate import require_totp
from i18n import t
from services.errors import InvalidOperation, ServiceError
from services.first_setup import FirstSetupService, SetupView
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


def _setup(services: Services) -> FirstSetupService:
    setup = services.first_setup
    if setup is None:
        raise ServiceError("первичная настройка недоступна", key="setup_unavailable")
    return setup


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


def _run_id(data: str) -> int:
    return int(data.rsplit(":", 1)[-1])


async def _show(callback: CallbackQuery, services: Services, view: SetupView) -> None:
    assert callback.message is not None
    await safe_edit_message_text(callback.message, setup_text(view), reply_markup=setup_keyboard(view))
    if view.message_id != callback.message.message_id:
        await _setup(services).attach_message(view.run_id, callback.message.message_id)


@router.callback_query(F.data == "setup:start")
async def setup_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        await state.clear()
        view = await _setup(services).begin(callback.from_user.id, chat_id=callback.message.chat.id)
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "setup:later")
async def setup_later(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await safe_callback_answer(callback, t("setup_later_hint"), show_alert=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:show:[0-9]{1,10}$"))
async def setup_show(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        view = await _setup(services).get(_run_id(callback.data))
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:ask:(domain|token):[0-9]{1,10}$"))
async def setup_ask(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.message is not None
        what = callback.data.split(":")[2]
        run_id = _run_id(callback.data)
        if what == "token" and not await require_totp(callback, state, services, action="dns_token"):
            return
        await state.set_state(SetupStates.domain if what == "domain" else SetupStates.token)
        await state.update_data(setup_run=run_id)
        await safe_callback_answer(callback)
        await callback.message.answer(t(f"setup_type_{what}"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _typed(message: Message, state: FSMContext, services: Services, what: str) -> None:
    raw = message.text or ""
    if what == "token":
        # The token goes away FIRST, whatever the message holds — then the check.
        try:
            await message.delete()
        except Exception:
            logger.warning("First setup: the message with the Cloudflare token could not be deleted — delete it by hand")
            await message.answer(t("cert_token_delete_by_hand"))
    try:
        if message.from_user is None or not await ensure_private_message(message, t("admin_private_only_text")):
            return
        await require_superadmin(services, message.from_user.id)
        data = await state.get_data()
        run_id = int(data.get("setup_run") or 0)
        setup = _setup(services)
        try:
            if what == "domain":
                view = await setup.submit_domain(message.from_user.id, run_id, raw)
            else:
                view = await setup.submit_token(message.from_user.id, run_id, raw)
        except InvalidOperation as exc:
            await message.answer(f"{h(service_error_text(exc))}\n{t('setup_try_again')}")
            return
        await state.clear()
        sent = await message.answer(setup_text(view), reply_markup=setup_keyboard(view))
        await setup.attach_message(view.run_id, sent.message_id)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(SetupStates.domain)
async def setup_domain_input(message: Message, state: FSMContext, services: Services) -> None:
    await _typed(message, state, services, "domain")


@router.message(SetupStates.token)
async def setup_token_input(message: Message, state: FSMContext, services: Services) -> None:
    await _typed(message, state, services, "token")


@router.callback_query(F.data.regexp(r"^setup:proto:[a-z0-9]+:[0-9]{1,10}$"))
async def setup_toggle(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        proto = callback.data.split(":")[2]
        view = await _setup(services).toggle(callback.from_user.id, _run_id(callback.data), proto)
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:go:[0-9]{1,10}$"))
async def setup_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """The one confirmation of the certificate, the installs, the firewall."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        if not await require_totp(callback, state, services, action="first_setup"):
            return
        view = await _setup(services).confirm_protocols(callback.from_user.id, _run_id(callback.data))
        await safe_callback_answer(callback, t("setup_running"))
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:totp:(done|skip):[0-9]{1,10}$"))
async def setup_totp(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        skip = callback.data.split(":")[2] == "skip"
        view = await _setup(services).totp_choice(callback.from_user.id, _run_id(callback.data), skip=skip)
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:retry:[0-9]{1,10}$"))
async def setup_retry(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        if not await require_totp(callback, state, services, action="first_setup"):
            return
        view = await _setup(services).retry(callback.from_user.id, _run_id(callback.data))
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^setup:cancel:[0-9]{1,10}$"))
async def setup_cancel(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        view = await _setup(services).cancel(callback.from_user.id, _run_id(callback.data))
        await safe_callback_answer(callback)
        await _show(callback, services, view)
    except Exception as exc:
        await answer_callback_error(callback, exc)


class SetupNotifier:
    """The setup's message when a wizard run moved it on (no callback to answer): sent
    anew under the run's own report, so the superadmin sees where the setup stands."""

    def __init__(self, bot: Bot, service: FirstSetupService) -> None:
        self.bot = bot
        self.service = service

    async def __call__(self, view: SetupView, fresh: bool) -> None:
        chat = view.chat_id or view.started_by
        if chat is None:
            return
        text, markup = setup_text(view), setup_keyboard(view)
        if not fresh and view.message_id is not None:
            try:
                await self.bot.edit_message_text(text, chat_id=chat, message_id=view.message_id, reply_markup=markup)
                return
            except Exception as exc:
                logger.info("first setup %d: message not editable (%s) — sending a new one", view.run_id, exc)
        sent = await self.bot.send_message(chat, text, reply_markup=markup)
        await self.service.attach_message(view.run_id, sent.message_id)
