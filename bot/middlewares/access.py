
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from typing import override
except ImportError:
    from typing_extensions import override

from aiogram import BaseMiddleware
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, TelegramObject

from bot.messages import safe_callback_answer
from models.access import is_blocked_user
from services.errors import NotFound
from services.users import UserService

BLOCKED_MESSAGE_TEXT = "🚫 Доступ к боту заблокирован. Напишите /start для повторной заявки."
BLOCKED_CALLBACK_TEXT = "🚫 Доступ заблокирован. Напишите /start для повторной заявки."
BLOCKED_START_TEXT = (
    "🚫 Ваш доступ к боту заблокирован.\n\n"
    "Вы можете повторно отправить заявку на доступ через /start.\n"
    "До повторного одобрения команды и кнопки недоступны."
)


class BlockedUserMiddleware(BaseMiddleware):
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
        if isinstance(event, Message) and _is_start_command(event):
            return await handler(event, data)
        try:
            user = await self.users.get_user(tg_user.id)
        except NotFound:
            return await handler(event, data)
        if not is_blocked_user(user):
            return await handler(event, data)
        await _clear_state(data)
        if isinstance(event, Message):
            await event.answer(BLOCKED_MESSAGE_TEXT)
        elif isinstance(event, CallbackQuery):
            await safe_callback_answer(event, BLOCKED_CALLBACK_TEXT, show_alert=True)
        return None


def _is_start_command(message: Message) -> bool:
    text = message.text
    if text is None:
        return False
    stripped = text.strip()
    if not stripped:
        return False
    first = stripped.split(maxsplit=1)[0]
    command, _, _bot_username = first.partition("@")
    return command == "/start"


async def _clear_state(data: dict[str, Any]) -> None:
    state = data.get("state")
    if isinstance(state, FSMContext):
        await state.clear()
    elif state is not None and hasattr(state, "clear"):
        await state.clear()  # type: ignore[union-attr]
