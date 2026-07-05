
import logging
from datetime import datetime, timezone

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import MaintenanceStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.admin import maintenance_enable_skip_keyboard, maintenance_panel_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from i18n import t

router = Router()
logger = logging.getLogger(__name__)


def _panel_text(services: Services) -> str:
    """Render the maintenance panel body from the in-memory snapshot."""
    state = services.maintenance.snapshot()
    lines = [t("maintenance_panel_title"), ""]
    if state.enabled:
        lines.append(t("maintenance_status_on"))
        if state.started_at:
            started = datetime.fromtimestamp(state.started_at, tz=timezone.utc)
            lines.append(t("maintenance_started_at", time=started.strftime("%Y-%m-%d %H:%M UTC")))
        lines.append("")
        lines.append(t("maintenance_current_banner", banner=services.maintenance.banner_text()))
    else:
        lines.append(t("maintenance_status_off"))
    return "\n".join(lines)


@router.callback_query(F.data == "admin:maintenance")
async def admin_maintenance_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Open the maintenance panel."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await state.clear()
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            _panel_text(services),
            reply_markup=maintenance_panel_keyboard(services.maintenance.is_enabled()),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:maintenance:enable")
async def admin_maintenance_enable_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Ask the admin for a banner message before enabling maintenance."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        await state.set_state(MaintenanceStates.waiting_message)
        await safe_edit_message_text(
            callback.message,
            t("maintenance_enable_prompt"),
            reply_markup=maintenance_enable_skip_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(MaintenanceStates.waiting_message)
async def admin_maintenance_enable_message(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """Enable maintenance with the admin-typed banner and broadcast the notice."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    await state.clear()
    try:
        await require_superadmin(services, message.from_user.id)
        await _enable_and_broadcast(message.from_user.id, message.text, services, bot)
        await message.answer(
            _panel_text(services),
            reply_markup=maintenance_panel_keyboard(True),
        )
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "admin:maintenance:enable:default")
async def admin_maintenance_enable_default(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    """Enable maintenance with the default banner (no custom text)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await state.clear()
    await safe_callback_answer(callback, t("maintenance_enabling"))
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await _enable_and_broadcast(callback.from_user.id, None, services, bot)
        await safe_edit_message_text(
            callback.message,
            _panel_text(services),
            reply_markup=maintenance_panel_keyboard(True),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:maintenance:disable")
async def admin_maintenance_disable(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    """Disable maintenance and broadcast that works are finished."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await state.clear()
    await safe_callback_answer(callback, t("maintenance_disabling"))
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await services.maintenance.disable(callback.from_user.id)
        result = await services.announcements.send_text_to_all(
            actor_user_id=callback.from_user.id,
            bot=bot,
            text=t("maintenance_broadcast_off"),
        )
        await safe_edit_message_text(
            callback.message,
            _panel_text(services) + "\n\n" + t("maintenance_disabled_ok", count=result.success),
            reply_markup=maintenance_panel_keyboard(False),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _enable_and_broadcast(actor_id: int, message: str | None, services: Services, bot: Bot) -> None:
    """Enable maintenance, then push the on-banner to all users (best-effort)."""
    await services.maintenance.enable(actor_id, message)
    await services.announcements.send_text_to_all(
        actor_user_id=actor_id,
        bot=bot,
        text=t("maintenance_broadcast_on", banner=services.maintenance.banner_text()),
    )
