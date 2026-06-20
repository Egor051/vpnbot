
import logging
import re
from contextlib import suppress

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, InaccessibleMessage, InlineKeyboardMarkup, Message

from models.dto import VpnKey
from utils.formatting import h, pre

logger = logging.getLogger(__name__)

MAX_TEXT_CONFIG_LEN = 3500
TELEGRAM_TEXT_LIMIT = 4096
AWG_CONFIG_FILENAME = "awg.conf"
_AWG_GENERATED_NAME_RE = re.compile(r"^awg_[A-Za-z0-9]{5}$")
_TRUNCATED_SUFFIX = "\n...обрезано"

# FSM data keys used to track the config file most recently delivered to the
# user. The message id lets us delete that file when the user taps another
# button, and the key id lets the "show config" button avoid sending it twice.
_CONFIG_DOC_MSG_KEY = "config_doc_msg_id"
_CONFIG_DOC_KEY_KEY = "config_doc_key_id"


async def remember_config_document(state: FSMContext, *, key_id: int, message_id: int) -> None:
    """Record the just-sent config file so it can be reused/cleaned up later."""
    await state.update_data({_CONFIG_DOC_MSG_KEY: message_id, _CONFIG_DOC_KEY_KEY: key_id})


async def config_document_present(state: FSMContext, key_id: int) -> bool:
    """Return whether a config file for ``key_id`` is currently on screen."""
    data = await state.get_data()
    return data.get(_CONFIG_DOC_KEY_KEY) == key_id and data.get(_CONFIG_DOC_MSG_KEY) is not None


async def discard_config_document(state: FSMContext, bot: Bot, chat_id: int) -> None:
    """Delete the tracked config file (if any) and forget it."""
    data = await state.get_data()
    msg_id = data.get(_CONFIG_DOC_MSG_KEY)
    if msg_id is None:
        return
    with suppress(Exception):
        await bot.delete_message(chat_id=chat_id, message_id=int(msg_id))
    await state.update_data({_CONFIG_DOC_MSG_KEY: None, _CONFIG_DOC_KEY_KEY: None})


async def safe_edit_message_text(
    message: Message | InaccessibleMessage | None,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> bool:
    if message is None or isinstance(message, InaccessibleMessage):
        return False
    text = cap_telegram_html(text)
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


def message_target_key(message: Message | InaccessibleMessage | None) -> tuple[int, int] | None:
    """Return a stable ``(chat_id, message_id)`` key for a message, or ``None``.

    Used to track per-message background work (e.g. the server-status auto-refresh
    loop) so it can be started and cancelled from different handlers.
    """
    if message is None:
        return None
    return (message.chat.id, message.message_id)


async def edit_message_for_refresh(
    message: Message | InaccessibleMessage | None,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> bool:
    """Edit a message in place for an auto-refresh loop.

    Returns ``True`` while the card is still present — including when the new
    content is byte-for-byte identical to the old (Telegram rejects that, but for
    a periodic refresh it just means "nothing changed, keep going"). Returns
    ``False`` once the message can no longer be edited (deleted or otherwise
    inaccessible) so the caller can stop the loop. Unlike
    :func:`safe_edit_message_text` it never re-posts a fresh message, so an
    abandoned card is not resurrected on every tick.
    """
    if message is None or isinstance(message, InaccessibleMessage):
        return False
    text = cap_telegram_html(text)
    try:
        await message.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest as exc:
        if _is_message_not_modified(exc):
            return True
        if _is_edit_unavailable(exc):
            return False
        raise
    return True


async def safe_callback_answer(
    callback: CallbackQuery,
    text: str | None = None,
    *,
    show_alert: bool | None = None,
    url: str | None = None,
    cache_time: int | None = None,
) -> bool:
    try:
        await callback.answer(text=text, show_alert=show_alert, url=url, cache_time=cache_time)
    except TelegramBadRequest as exc:
        if is_stale_callback_query_error(exc):
            logger.debug("Ignoring stale Telegram callback query answer: %s", exc)
            return False
        logger.warning("Telegram callback query answer failed", exc_info=True)
        raise
    return True


async def send_awg_config(
    message: Message | InaccessibleMessage | None,
    *,
    title: str,
    config_text: str,
    filename: str = AWG_CONFIG_FILENAME,
    reply_markup: InlineKeyboardMarkup | None = None,
    edit_text: bool = False,
    send_document: bool = True,
) -> None:
    if message is None or isinstance(message, InaccessibleMessage):
        return
    if len(config_text) <= MAX_TEXT_CONFIG_LEN:
        text = cap_telegram_html(f"<b>{h(title)}</b>\n\n{pre(config_text)}")
        if edit_text:
            await safe_edit_message_text(message, text, reply_markup=reply_markup)
        else:
            await message.answer(text, reply_markup=reply_markup)
        document_reply_markup = None
        document_caption = cap_telegram_html(f"{h(title)}\nФайл конфигурации: {h(filename)}", limit=1024)
    else:
        text = cap_telegram_html(f"{h(title)}\nКонфиг отправлен файлом, потому что он слишком длинный для сообщения.")
        if edit_text:
            await safe_edit_message_text(message, text, reply_markup=reply_markup)
        else:
            await message.answer(text, reply_markup=reply_markup)
        document_reply_markup = None
        document_caption = text

    if not send_document and len(config_text) <= MAX_TEXT_CONFIG_LEN:
        return

    document = BufferedInputFile(config_text.encode("utf-8"), filename=filename)
    await message.answer_document(
        document,
        caption=document_caption,
        disable_content_type_detection=False,
        reply_markup=document_reply_markup,
    )


def awg_config_filename(key: VpnKey) -> str:
    label = key.email_label or str(key.public_payload.get("email_label") or "")
    if _AWG_GENERATED_NAME_RE.fullmatch(label):
        return f"{label}.conf"
    return AWG_CONFIG_FILENAME


def cap_telegram_html(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> str:
    if len(text) <= limit:
        return text
    suffix = _TRUNCATED_SUFFIX
    if limit <= len(suffix):
        return suffix[-limit:]
    raw_limit = limit - len(suffix)
    cut = text.rfind("\n", 0, raw_limit)
    if cut < raw_limit // 2:
        cut = raw_limit
    snippet = text[:cut].rstrip()
    last_lt = snippet.rfind("<")
    last_gt = snippet.rfind(">")
    if last_lt > last_gt:
        snippet = snippet[:last_lt].rstrip()
    snippet = _trim_partial_entity(snippet)
    closing = _closing_tags(snippet)
    if len(snippet) + len(closing) + len(suffix) > limit:
        snippet = snippet[: max(limit - len(closing) - len(suffix), 0)].rstrip()
        last_lt = snippet.rfind("<")
        last_gt = snippet.rfind(">")
        if last_lt > last_gt:
            snippet = snippet[:last_lt].rstrip()
        snippet = _trim_partial_entity(snippet)
        closing = _closing_tags(snippet)
    return snippet + closing + suffix


def _trim_partial_entity(text: str) -> str:
    """Drop a trailing HTML entity that was cut in half (e.g. ``&amp;`` -> ``&am``).

    Only a short dangling ``&...`` with no terminating ``;`` is removed, so a
    bare ampersand earlier in the text is left untouched.
    """
    amp = text.rfind("&")
    if amp == -1 or ";" in text[amp:]:
        return text
    if len(text) - amp <= 10:  # max length of a real entity (&#x1F600; etc.)
        return text[:amp].rstrip()
    return text


def _closing_tags(text: str) -> str:
    # Telegram-supported simple tags emitted by the formatters. ``<a>`` is
    # intentionally omitted: it carries attributes (``<a href=...>``) so it
    # cannot match this pattern, and no formatter currently emits links.
    stack: list[str] = []
    for match in re.finditer(r"</?(b|i|u|s|code|pre|blockquote)>", text):
        tag = match.group(1)
        if match.group(0).startswith("</"):
            if tag in stack:
                stack.pop(len(stack) - 1 - stack[::-1].index(tag))
            continue
        stack.append(tag)
    return "".join(f"</{tag}>" for tag in reversed(stack))


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


def is_stale_callback_query_error(exc: Exception) -> bool:
    if not isinstance(exc, TelegramBadRequest):
        return False
    message = str(exc).lower()
    return any(
        text in message
        for text in (
            "query is too old",
            "response timeout expired",
            "query id is invalid",
        )
    )
