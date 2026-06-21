
import logging

from aiogram import F, Router
from aiogram.types import CallbackQuery, InaccessibleMessage, Message

from bot.container import Services
from bot.formatters import dashboard_text, server_status_text
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error
from bot.keyboards.admin import admin_panel_keyboard, dashboard_keyboard, server_status_keyboard
from bot.messages import (
    edit_message_for_refresh,
    message_target_key,
    safe_callback_answer,
    safe_edit_message_text,
)
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
        status = await services.server_status.snapshot_averaged()
        online = await services.online_clients.get()
        await safe_edit_message_text(
            callback.message,
            server_status_text(status, online),
            reply_markup=server_status_keyboard(services.server_status.detailed),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _start_server_status_auto_refresh(callback: CallbackQuery, services: Services) -> None:
    """Keep the server-status card live: re-render it every few seconds for up to
    an hour, then fall back to the admin panel so an abandoned card stops
    sampling the host. Re-opening the panel restarts the timer; navigating away
    cancels it (see the ``admin:panel`` handler)."""
    message = callback.message
    user = callback.from_user
    if user is None or message is None or isinstance(message, InaccessibleMessage):
        return
    key = message_target_key(message)
    if key is None:
        return
    user_id = user.id

    async def refresh() -> bool:
        try:
            await require_superadmin(services, user_id)
            status = await services.server_status.snapshot_averaged()
            online = await services.online_clients.get()
        except Exception:
            logger.debug("server status auto-refresh snapshot failed", exc_info=True)
            return False
        return await edit_message_for_refresh(
            message,
            server_status_text(status, online),
            reply_markup=server_status_keyboard(services.server_status.detailed),
        )

    async def on_expire() -> None:
        await edit_message_for_refresh(
            message,
            t("admin_panel_title"),
            reply_markup=admin_panel_keyboard(),
        )

    services.auto_refresh.start(key, refresh=refresh, on_expire=on_expire)


def stop_server_status_auto_refresh(message: Message | InaccessibleMessage | None, services: Services) -> None:
    """Cancel the auto-refresh loop bound to ``message`` (used when navigating away)."""
    key = message_target_key(message)
    if key is not None:
        services.auto_refresh.cancel(key)


@router.callback_query(F.data == "admin:server_status")
async def admin_server_status(callback: CallbackQuery, services: Services) -> None:
    """Open the real-time server status panel."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("updating_server_status"))
    await _render_server_status(callback, services)
    _start_server_status_auto_refresh(callback, services)


@router.callback_query(F.data == "admin:server_status:toggle_detailed")
async def admin_server_status_toggle_detailed(callback: CallbackQuery, services: Services) -> None:
    """Toggle detailed-metrics collection (load average, uptime, network history).

    Persists the new state to the DB and flips the sampler's in-memory flag so
    background collection starts/stops immediately, then re-renders the panel.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        new_state = not services.server_status.detailed
        await services.server_status_settings.set_detailed(new_state)
        services.server_status.set_detailed(new_state)
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    await safe_callback_answer(callback)
    await _render_server_status(callback, services)
    _start_server_status_auto_refresh(callback, services)
