from __future__ import annotations

from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Message

from bot.messages import safe_callback_answer


PRIVATE_ONLY_TEXT = "Эта операция доступна только в личном чате с ботом."
ADMIN_PRIVATE_ONLY_TEXT = "Админ-панель доступна только в личном чате с ботом."


def _is_private_chat(message: Message | None) -> bool:
    return message is not None and message.chat.type == ChatType.PRIVATE


async def ensure_private_message(message: Message, text: str = PRIVATE_ONLY_TEXT) -> bool:
    if _is_private_chat(message):
        return True
    await message.answer(text)
    return False


async def ensure_private_callback(callback: CallbackQuery, text: str = PRIVATE_ONLY_TEXT) -> bool:
    message = callback.message if isinstance(callback.message, Message) else None
    if _is_private_chat(message):
        return True
    await safe_callback_answer(callback, text, show_alert=True)
    return False
