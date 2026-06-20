
import logging

from aiogram import F, Router
from aiogram.types import CallbackQuery

from bot.container import Services
from bot.formatters import dashboard_text, server_status_text
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error
from bot.keyboards.admin import dashboard_keyboard, server_status_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from i18n import t

router = Router()
logger = logging.getLogger(__name__)


async def _render_dashboard(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        snapshot = await services.dashboard.build_snapshot()
        await safe_edit_message_text(
            callback.message,
            dashboard_text(snapshot),
            reply_markup=dashboard_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:dashboard")
async def admin_dashboard(callback: CallbackQuery, services: Services) -> None:
    """Open the admin live dashboard."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    await _render_dashboard(callback, services)


@router.callback_query(F.data == "admin:dashboard:refresh")
async def admin_dashboard_refresh(callback: CallbackQuery, services: Services) -> None:
    """Refresh the admin live dashboard in place."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, "Обновляю...")
    await _render_dashboard(callback, services)


async def _render_server_status(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        status = await services.server_status.snapshot()
        await safe_edit_message_text(
            callback.message,
            server_status_text(status),
            reply_markup=server_status_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:server_status")
async def admin_server_status(callback: CallbackQuery, services: Services) -> None:
    """Open the real-time server status panel."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("updating_server_status"))
    await _render_server_status(callback, services)


@router.callback_query(F.data == "admin:server_status:refresh")
async def admin_server_status_refresh(callback: CallbackQuery, services: Services) -> None:
    """Refresh the server status panel in place."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("updating_server_status"))
    await _render_server_status(callback, services)
