from __future__ import annotations

from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Message


PRIVATE_ONLY_TEXT = "Эта операция доступна только в личном чате с ботом."


def _is_private_chat(message: Message | None) -> bool:
    return message is not None and message.chat.type == ChatType.PRIVATE


async def ensure_private_message(message: Message) -> bool:
    if _is_private_chat(message):
        return True
    await message.answer(PRIVATE_ONLY_TEXT)
    return False


async def ensure_private_callback(callback: CallbackQuery) -> bool:
    message = callback.message if isinstance(callback.message, Message) else None
    if _is_private_chat(message):
        return True
    await callback.answer(PRIVATE_ONLY_TEXT, show_alert=True)
    return False
