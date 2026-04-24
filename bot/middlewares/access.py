from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from models.enums import UserRole
from services.errors import NotFound
from services.users import UserService


class BlockedUserMiddleware(BaseMiddleware):
    def __init__(self, users: UserService) -> None:
        self.users = users

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        tg_user = data.get("event_from_user")
        if tg_user is None:
            return await handler(event, data)
        if isinstance(event, Message) and event.text and event.text.startswith("/start"):
            return await handler(event, data)
        try:
            user = await self.users.get_user(tg_user.id)
        except NotFound:
            return await handler(event, data)
        if user.role != UserRole.BLOCKED_USER:
            return await handler(event, data)
        if isinstance(event, Message):
            await event.answer("Ваш доступ заблокирован.")
        elif isinstance(event, CallbackQuery):
            await event.answer("Ваш доступ заблокирован.", show_alert=True)
        return None
