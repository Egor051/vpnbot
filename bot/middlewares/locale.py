
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from typing import override
except ImportError:
    from typing_extensions import override

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject

import i18n
from services.errors import NotFound
from services.users import UserService


class LocaleMiddleware(BaseMiddleware):
    """Activate each user's stored language for the duration of an update.

    Uses i18n's per-task ContextVar so concurrent updates from users with
    different languages never race. Users without a stored preference keep the
    global default configured from BOT_LANGUAGE.
    """

    def __init__(self, users: UserService) -> None:
        self.users = users

    @override
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        tg_user = data.get("event_from_user")
        if tg_user is None:
            return await handler(event, data)
        language: str | None = None
        try:
            user = await self.users.get_user(tg_user.id)
            language = user.language
        except NotFound:
            language = None
        if language is None:
            return await handler(event, data)
        token = i18n.set_locale(language)
        try:
            return await handler(event, data)
        finally:
            i18n.reset_locale(token)
