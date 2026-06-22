
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from typing import override
except ImportError:
    from typing_extensions import override

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, InlineQuery, Message, TelegramObject

from bot.messages import safe_callback_answer
from bot.middlewares.access import _clear_state
from config.settings import Settings
from services.maintenance import MaintenanceService


class MaintenanceModeMiddleware(BaseMiddleware):
    """Gate every update while maintenance mode is on.

    When maintenance is off this is a no-op with zero database access (the common
    case). When on, only superadmins (identified by ``settings.admin_ids``, the
    config source of truth for superadmins) pass through; everyone else gets the
    maintenance banner and their update is dropped.
    """

    def __init__(self, maintenance: MaintenanceService, settings: Settings) -> None:
        self.maintenance = maintenance
        self.settings = settings

    @override
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not self.maintenance.is_enabled():
            return await handler(event, data)
        tg_user = data.get("event_from_user")
        if tg_user is None:
            return await handler(event, data)
        if tg_user.id in self.settings.admin_ids:
            return await handler(event, data)
        await _clear_state(data)
        banner = self.maintenance.banner_text()
        if isinstance(event, Message):
            await event.answer(banner)
        elif isinstance(event, CallbackQuery):
            await safe_callback_answer(event, banner, show_alert=True)
        elif isinstance(event, InlineQuery):
            await event.answer(results=[], cache_time=60, is_personal=True)
        return None
