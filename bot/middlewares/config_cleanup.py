
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from typing import override
except ImportError:
    from typing_extensions import override

from aiogram import Bot, BaseMiddleware
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InaccessibleMessage, TelegramObject

from bot.messages import discard_config_document

# Tapping a "show config" button must not delete the messages it (re)sends, so
# those callbacks are the single exception to the cleanup below. Both «Конфиг»
# buttons are listed: the per-key one and the bundle/subscription one, which now
# delivers a QR under the same tracking. They stay distinguishable in the tracked
# state via its ``kind`` discriminator, so an exempted bundle tap cannot mistake a
# tracked key config for its own.
_SHOW_CONFIG_PREFIXES = ("key:show:", "bundle:show:")


class ConfigDocumentCleanupMiddleware(BaseMiddleware):
    """Delete previously sent config messages when the user taps another button."""

    @override
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if isinstance(event, CallbackQuery):
            await self._maybe_cleanup(event, data)
        return await handler(event, data)

    @staticmethod
    async def _maybe_cleanup(callback: CallbackQuery, data: dict[str, Any]) -> None:
        if (callback.data or "").startswith(_SHOW_CONFIG_PREFIXES):
            return
        message = callback.message
        if message is None or isinstance(message, InaccessibleMessage):
            return
        state = data.get("state")
        bot = data.get("bot")
        if isinstance(state, FSMContext) and isinstance(bot, Bot):
            await discard_config_document(state, bot, message.chat.id)
