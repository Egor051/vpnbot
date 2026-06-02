
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
    message = callback.message
    # Both Message and InaccessibleMessage expose ``chat``, so the private-chat
    # check works even for an old/deleted message.
    if message is None or message.chat.type != ChatType.PRIVATE:
        await safe_callback_answer(callback, text or t("private_only_text"), show_alert=True)
        return False
    if not isinstance(message, Message):
        # Private chat, but the message is no longer accessible (older than 48h
        # or deleted): we can't edit it. Tell the user instead of falsely
        # claiming the action is group-only, and stop before handlers touch it.
        await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        return False
    return True
