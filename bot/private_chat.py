
from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Message

from bot.messages import safe_callback_answer
from i18n import t


def _is_private_chat(message: Message | None) -> bool:
    return message is not None and message.chat.type == ChatType.PRIVATE


async def ensure_private_message(message: Message, text: str | None = None) -> bool:
    if _is_private_chat(message):
        return True
    await message.answer(text or t("private_only_text"))
    return False


async def ensure_private_callback(callback: CallbackQuery, text: str | None = None) -> bool:
    message = callback.message if isinstance(callback.message, Message) else None
    if _is_private_chat(message):
        return True
    await safe_callback_answer(callback, text or t("private_only_text"), show_alert=True)
    return False
