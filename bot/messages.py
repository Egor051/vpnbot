from __future__ import annotations

from aiogram.exceptions import TelegramBadRequest
from aiogram.types import BufferedInputFile, InlineKeyboardMarkup, Message

from utils.formatting import h, pre

MAX_TEXT_CONFIG_LEN = 3500
AWG_CONFIG_FILENAME = "awg.conf"


async def safe_edit_message_text(
    message: Message,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> bool:
    try:
        await message.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest as exc:
        if _is_message_not_modified(exc):
            return False
        if _is_edit_unavailable(exc):
            await message.answer(text, reply_markup=reply_markup)
            return True
        raise
    return True


async def send_awg_config(
    message: Message,
    *,
    title: str,
    config_text: str,
    filename: str = AWG_CONFIG_FILENAME,
    reply_markup: InlineKeyboardMarkup | None = None,
    edit_text: bool = False,
    send_document: bool = True,
) -> None:
    text_was_updated = True
    if len(config_text) <= MAX_TEXT_CONFIG_LEN:
        text = f"<b>{h(title)}</b>\n\n{pre(config_text)}"
        if edit_text:
            text_was_updated = await safe_edit_message_text(message, text, reply_markup=reply_markup)
        else:
            await message.answer(text, reply_markup=reply_markup)
        document_reply_markup = None
        document_caption = f"{h(title)}\nФайл конфигурации: {h(filename)}"
    else:
        text = f"{h(title)}\nКонфиг отправлен файлом, потому что он слишком длинный для сообщения."
        if edit_text:
            text_was_updated = await safe_edit_message_text(message, text, reply_markup=reply_markup)
        else:
            await message.answer(text, reply_markup=reply_markup)
        document_reply_markup = None
        document_caption = text

    if not send_document and len(config_text) <= MAX_TEXT_CONFIG_LEN:
        return

    if edit_text and not text_was_updated:
        return

    document = BufferedInputFile(config_text.encode("utf-8"), filename=filename)
    await message.answer_document(
        document,
        caption=document_caption,
        disable_content_type_detection=False,
        reply_markup=document_reply_markup,
    )


def _is_message_not_modified(exc: TelegramBadRequest) -> bool:
    return "message is not modified" in str(exc).lower()


def _is_edit_unavailable(exc: TelegramBadRequest) -> bool:
    message = str(exc).lower()
    return any(
        text in message
        for text in (
            "message to edit not found",
            "message can't be edited",
            "there is no text in the message to edit",
            "message is not found",
        )
    )
