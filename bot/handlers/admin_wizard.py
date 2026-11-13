"""«🧙 Мастер настройки» in the admin panel (docs/wizard.md). SUPERADMIN only.

The handlers start, confirm and cancel runs and show them; the run itself is a fixed
root helper in its own systemd unit (services/wizard.py), and the background monitor
(bot/wizard_notifier.py) keeps the run's one message up to date — before and after a
restart of the bot. Dangerous modes ask for the TOTP code (bot/totp_gate.py) both
before they start and before a plan is applied.
"""

from __future__ import annotations

import logging

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.totp_gate import require_totp
from bot.wizard_views import history_keyboard, history_text, menu_keyboard, mode_title, run_view
from i18n import t
from services.errors import ServiceError
from services.wizard import WizardService
from services.wizard_modes import MODES, get_mode
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)
HISTORY_PAGE_SIZE = 8


def _wizard(services: Services) -> WizardService:
    if services.wizard is None:
        raise ServiceError("мастер не подключён", key="wizard_unavailable")
    return services.wizard


def _run_id(data: str) -> int:
    tail = data.rsplit(":", 1)[-1]
    if not tail.isdigit() or not 0 < int(tail) < 10**9:
        raise ServiceError("плохой номер запуска", key="wizard_run_not_found")
    return int(tail)


async def menu_view(services: Services) -> tuple[str, InlineKeyboardMarkup]:
    wizard = _wizard(services)
    active = await wizard.active()
    daily = await wizard.daily_selfcheck_enabled()
    lines = [t("wizard_title")]
    if not wizard.installed():
        lines += ["", t("wizard_not_installed")]
    if active is not None:
        lines += ["", t("wizard_active_line", id=active.id, mode=h(mode_title(active.mode)))]
    lines += ["", t("wizard_daily_line_on") if daily else t("wizard_daily_line_off")]
    return "\n".join(lines), menu_keyboard(active=active, daily=daily)


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


@router.callback_query(F.data == "wiz:menu")
async def wizard_menu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await state.clear()
        text, markup = await menu_view(services)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:start:[a-z]+$"))
async def wizard_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None and callback.message is not None
        mode = get_mode(callback.data.rsplit(":", 1)[-1])
        if mode.dangerous and not await require_totp(callback, state, services, action=f"wizard_{mode.key}"):
            return
        wizard = _wizard(services)
        async with wizard.exclusive():
            run = await wizard.start(
                callback.from_user.id,
                mode.key,
                chat_id=callback.message.chat.id,
                message_id=callback.message.message_id,
            )
            await safe_callback_answer(callback, t("wizard_started", id=run.id))
            text, markup = run_view(run, await wizard.snapshot(run.id))
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:ok:\d+$"))
async def wizard_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None and callback.message is not None
        wizard = _wizard(services)
        run = await wizard.get(_run_id(callback.data))
        mode = MODES.get(run.mode)
        if mode is not None and mode.dangerous and not await require_totp(callback, state, services, action=f"wizard_{mode.key}"):
            return
        async with wizard.exclusive():
            run = await wizard.confirm(callback.from_user.id, run.id)
            await wizard.attach_message(run.id, callback.message.chat.id, callback.message.message_id)
            await safe_callback_answer(callback, t("wizard_confirmed"))
            text, markup = run_view(await wizard.get(run.id), await wizard.snapshot(run.id))
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:no:\d+$"))
async def wizard_cancel(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None
        wizard = _wizard(services)
        # The same lock as «Применить» and the monitor: the two buttons of one plan
        # never interleave (the repository transitions are atomic on top of that).
        async with wizard.exclusive():
            run = await wizard.cancel(callback.from_user.id, _run_id(callback.data))
            await safe_callback_answer(callback, t("wizard_cancelled"))
            text, markup = run_view(run, await wizard.snapshot(run.id))
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:run:\d+$"))
async def wizard_run_card(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        wizard = _wizard(services)
        run = await wizard.get(_run_id(callback.data))
        text, markup = run_view(run, await wizard.snapshot(run.id))
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:hist:\d+$"))
async def wizard_history(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        page = min(int(callback.data.rsplit(":", 1)[-1]), 1000)
        runs, total = await _wizard(services).history(HISTORY_PAGE_SIZE, page * HISTORY_PAGE_SIZE)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            history_text(runs, page, total),
            reply_markup=history_keyboard(runs, page, (page + 1) * HISTORY_PAGE_SIZE < total),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:log:\d+$"))
async def wizard_send_log(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None and callback.message is not None
        filename, data = await _wizard(services).log_document(callback.from_user.id, _run_id(callback.data))
        await safe_callback_answer(callback)
        await bot.send_document(callback.message.chat.id, BufferedInputFile(data, filename=filename))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wiz:art:\d+$"))
async def wizard_send_artifact(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.message is not None
        wizard = _wizard(services)
        run = await wizard.get(_run_id(callback.data))
        mode = MODES.get(run.mode)
        if mode is not None and mode.dangerous and not await require_totp(callback, state, services, action=f"wizard_{mode.key}"):
            return
        snap = await wizard.snapshot(run.id)
        doc = await wizard.artifact_document(run, snap.artifact) if snap.artifact else None
        if doc is None:
            await safe_callback_answer(callback, t("wizard_artifact_missing", id=run.id), show_alert=True)
            return
        await safe_callback_answer(callback)
        await bot.send_document(callback.message.chat.id, BufferedInputFile(doc[1], filename=doc[0]), caption=t("wizard_artifact_caption", id=run.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "wiz:sched")
async def wizard_toggle_schedule(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        wizard = _wizard(services)
        enabled = not await wizard.daily_selfcheck_enabled()
        await wizard.set_daily_selfcheck(callback.from_user.id, enabled)
        await safe_callback_answer(callback, t("wizard_daily_on") if enabled else t("wizard_daily_off"))
        text, markup = await menu_view(services)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)
