from __future__ import annotations

from aiogram.types import BufferedInputFile, InlineKeyboardMarkup, Message

from utils.formatting import h, pre

MAX_TEXT_CONFIG_LEN = 3500


async def send_awg_config(
    message: Message,
    *,
    title: str,
    config_text: str,
    filename: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    if len(config_text) <= MAX_TEXT_CONFIG_LEN:
        await message.answer(f"<b>{h(title)}</b>\n\n{pre(config_text)}", reply_markup=reply_markup)
        return
    document = BufferedInputFile(config_text.encode("utf-8"), filename=filename)
    await message.answer_document(
        document,
        caption=f"{h(title)}\nКонфиг отправлен файлом, потому что он слишком длинный для сообщения.",
        reply_markup=reply_markup,
    )
