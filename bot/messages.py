
import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from typing import Any

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, InaccessibleMessage, InlineKeyboardMarkup, Message

from models.dto import VpnKey
from utils.formatting import h, pre
from utils.qr import QrPayloadTooLarge, render_config_qr

logger = logging.getLogger(__name__)

MAX_TEXT_CONFIG_LEN = 3500
TELEGRAM_TEXT_LIMIT = 4096
AWG_CONFIG_FILENAME = "awg.conf"
_AWG_GENERATED_NAME_RE = re.compile(r"^awg_[A-Za-z0-9]{5}$")
_TRUNCATED_SUFFIX = "\n...обрезано"

# Upper bound on how long a one-shot, user-facing edit (``safe_edit_message_text``)
# will wait on a Telegram 429 (``TelegramRetryAfter.retry_after``) before retrying.
# This path runs inline with a human waiting on a button tap, so the clamp is
# deliberately short: a pathologically large ``retry_after`` must not make the
# user stare at a frozen UI. A larger value is clamped to this and the edit is
# retried once.
_MAX_REFRESH_RETRY_AFTER = 5.0

# Upper bound for the *live auto-refresh loop* path (``edit_message_for_refresh``),
# which edits a single ``message_id`` on a fixed cadence for up to an hour. Unlike
# the user-facing edit above, there is no human blocked on this tick, so it must
# honour a realistic penalty window: clamping to a few seconds and then re-poking
# the same message mid-cooldown only prolongs Telegram's flood ban (each early
# edit resets/extends it). A larger ceiling lets one tick actually wait the flood
# out; the loop's own cadence (``DEFAULT_INTERVAL_SECONDS``) keeps the panel alive.
_MAX_LIVE_REFRESH_RETRY_AFTER = 30.0

# FSM data keys used to track the config messages most recently delivered to the
# user. The message ids let us delete them when the user taps another button, and
# the entity id/kind let the "show config" button avoid sending them twice.
#
# ``_CONFIG_DOC_MSG_KEY`` holds a LIST of ids, not one: a single tap on «Конфиг»
# now delivers a config *and* its QR code, and the two have to disappear together
# — a QR outliving the config it encodes (or vice versa) is exactly the split-brain
# this tracking exists to prevent. Everything downstream (the cleanup middleware,
# the duplicate-send guard) is unchanged and still drives off these same keys.
#
# ``_CONFIG_DOC_KIND_KEY`` namespaces the tracked id. Keys and bundles number out
# of two independent id spaces, so key #10 and bundle #10 both exist; without the
# kind, a tracked key config would make the bundle screen's «Конфиг» believe its
# own config was already on screen and silently skip it. The two «Конфиг» buttons
# are the cleanup middleware's exemptions, so that stale-state window is reachable
# by scrolling back to an older bundle card and tapping it.
_CONFIG_DOC_MSG_KEY = "config_doc_msg_id"
_CONFIG_DOC_KEY_KEY = "config_doc_key_id"
_CONFIG_DOC_KIND_KEY = "config_doc_kind"

# Values for the ``kind`` discriminator above.
CONFIG_DOC_KIND_KEY = "key"
CONFIG_DOC_KIND_BUNDLE = "bundle"


async def remember_config_document(
    state: FSMContext,
    *,
    key_id: int,
    message_ids: Sequence[int],
    kind: str = CONFIG_DOC_KIND_KEY,
) -> None:
    """Record the just-sent config message(s) so they can be reused/cleaned up later.

    ``message_ids`` is every message that tap put on screen for this config — the
    ``.conf`` document and/or the QR photo — in send order. They are tracked as one
    unit and :func:`discard_config_document` removes them as one unit.
    """
    await state.update_data(
        {
            _CONFIG_DOC_MSG_KEY: list(message_ids),
            _CONFIG_DOC_KEY_KEY: key_id,
            _CONFIG_DOC_KIND_KEY: kind,
        }
    )


async def config_document_present(state: FSMContext, key_id: int, kind: str = CONFIG_DOC_KIND_KEY) -> bool:
    """Return whether config messages for ``key_id`` of ``kind`` are currently on screen."""
    data = await state.get_data()
    if data.get(_CONFIG_DOC_KEY_KEY) != key_id:
        return False
    if data.get(_CONFIG_DOC_KIND_KEY, CONFIG_DOC_KIND_KEY) != kind:
        return False
    return bool(_tracked_message_ids(data))


async def discard_config_document(state: FSMContext, bot: Bot, chat_id: int) -> None:
    """Delete every tracked config message (if any) and forget them."""
    data = await state.get_data()
    msg_ids = _tracked_message_ids(data)
    if not msg_ids:
        return
    for msg_id in msg_ids:
        # One failed delete (already gone, too old to delete) must not orphan the
        # rest of the group — the whole point is that they vanish together.
        with suppress(Exception):
            await bot.delete_message(chat_id=chat_id, message_id=msg_id)
    await state.update_data(
        {_CONFIG_DOC_MSG_KEY: None, _CONFIG_DOC_KEY_KEY: None, _CONFIG_DOC_KIND_KEY: None}
    )


def _tracked_message_ids(data: Mapping[str, Any]) -> list[int]:
    """Normalise the tracked ids out of FSM data, tolerating a bare int."""
    raw = data.get(_CONFIG_DOC_MSG_KEY)
    if raw is None:
        return []
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [int(item) for item in raw if item is not None]
    return []


# Filename on the QR photo upload. Telegram never shows it for a photo, so this is
# not a caption by another name — the QR is delivered with no caption and no
# accompanying text, identically for every key type.
_QR_FILENAME = "config-qr.png"


async def send_config_with_qr(
    message: Message | InaccessibleMessage | None,
    state: FSMContext,
    *,
    entity_id: int,
    qr_content: str,
    document: BufferedInputFile | None = None,
    kind: str = CONFIG_DOC_KIND_KEY,
) -> list[int]:
    """Deliver a config's own message(s) plus its QR code, tracked as one unit.

    ``qr_content`` must be verbatim what the user pastes into a client — the AWG
    ``.conf`` body, a ``vless://``/``hysteria2://`` URI, a bundle sub-URL. Passing
    the same string that is rendered/attached elsewhere is what keeps the QR and
    the text from ever drifting apart.

    ``document`` is the optional config file (AWG only today); protocols whose
    config is a single URI pass ``None`` and get the QR alone. Whatever is sent is
    registered with :func:`remember_config_document`, so the cleanup middleware
    removes it on the user's next tap — one trigger, one delete path, every type.

    A QR that cannot be rendered is logged and skipped, never truncated: the user
    still gets the config itself, which is the part they cannot connect without.
    """
    if message is None or isinstance(message, InaccessibleMessage):
        return []
    sent_ids: list[int] = []
    if document is not None:
        sent = await message.answer_document(document)
        sent_ids.append(sent.message_id)
    try:
        png = render_config_qr(qr_content)
    except (QrPayloadTooLarge, ValueError):
        # Never log ``qr_content`` — every payload here is a live credential.
        logger.warning(
            "Skipping config QR: payload of %d bytes could not be encoded",
            len(qr_content.encode("utf-8")),
            exc_info=True,
        )
    else:
        qr_message = await message.answer_photo(BufferedInputFile(png, filename=_QR_FILENAME))
        sent_ids.append(qr_message.message_id)
    if sent_ids:
        await remember_config_document(state, key_id=entity_id, message_ids=sent_ids, kind=kind)
    return sent_ids


async def safe_edit_message_text(
    message: Message | InaccessibleMessage | None,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> bool:
    if message is None or isinstance(message, InaccessibleMessage):
        return False
    text = cap_telegram_html(text)
    try:
        await message.edit_text(text, reply_markup=reply_markup)
    except TelegramRetryAfter as exc:
        # Telegram 429: wait the server-provided back-off (clamped to
        # ``_MAX_REFRESH_RETRY_AFTER`` so a pathological value cannot stall the
        # caller) and retry the edit exactly once. If the flood persists we leave
        # the message untouched and report "not applied" rather than re-posting a
        # fresh message — a transient flood must not orphan a duplicate card. For
        # the panel's first render the auto-refresh loop (which also honours 429)
        # will fill the original message in within ~1s.
        await sleep(min(exc.retry_after, _MAX_REFRESH_RETRY_AFTER))
        try:
            await message.edit_text(text, reply_markup=reply_markup)
        except TelegramRetryAfter:
            logger.debug("edit still rate-limited after retry; leaving message unchanged")
            return False
        except TelegramBadRequest as retry_exc:
            return await _safe_edit_outcome(retry_exc, message, text, reply_markup)
    except TelegramBadRequest as exc:
        return await _safe_edit_outcome(exc, message, text, reply_markup)
    return True


async def _safe_edit_outcome(
    exc: TelegramBadRequest,
    message: Message,
    text: str,
    reply_markup: InlineKeyboardMarkup | None,
) -> bool:
    """Map a failed :func:`safe_edit_message_text` edit to its boolean result.

    ``message is not modified`` means the content is already on screen, so the
    edit is a no-op (``False``). An edit-unavailable error means the message can
    no longer be edited, so the content is re-posted as a fresh message
    (``True``). Anything else is unexpected and re-raised. This mirrors the
    inline branches the function used to carry; it is *not*
    :func:`_refresh_edit_outcome`, which has the opposite semantics (not-modified
    keeps the card alive, unavailable stops the loop without re-posting).
    """
    if _is_message_not_modified(exc):
        return False
    if _is_edit_unavailable(exc):
        await message.answer(text, reply_markup=reply_markup)
        return True
    raise exc


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
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> bool:
    """Edit a message in place for an auto-refresh loop.

    Returns ``True`` while the card is still present — including when the new
    content is byte-for-byte identical to the old (Telegram rejects that, but for
    a periodic refresh it just means "nothing changed, keep going"). Returns
    ``False`` once the message can no longer be edited (deleted or otherwise
    inaccessible) so the caller can stop the loop. Unlike
    :func:`safe_edit_message_text` it never re-posts a fresh message, so an
    abandoned card is not resurrected on every tick.

    Telegram rate-limits frequent edits of one message with HTTP 429
    (:class:`~aiogram.exceptions.TelegramRetryAfter`). That back-off is honoured
    here, local to this Telegram-specific helper: on a 429 we wait the
    server-provided ``retry_after`` (clamped to
    :data:`_MAX_LIVE_REFRESH_RETRY_AFTER` so a pathological value cannot park the
    loop indefinitely, but generously enough that one tick actually waits out a
    realistic penalty window instead of re-poking the message mid-cooldown) and
    retry the edit exactly once. If the flood persists we keep the card alive and
    let the next tick try again rather than spinning on retries. ``sleep`` is
    injectable so tests can drive the back-off without real delays.
    """
    if message is None or isinstance(message, InaccessibleMessage):
        return False
    text = cap_telegram_html(text)
    try:
        await message.edit_text(text, reply_markup=reply_markup)
    except TelegramRetryAfter as exc:
        await sleep(min(exc.retry_after, _MAX_LIVE_REFRESH_RETRY_AFTER))
        try:
            await message.edit_text(text, reply_markup=reply_markup)
        except TelegramRetryAfter:
            logger.debug("live refresh still rate-limited after retry; skipping tick")
            return True
        except TelegramBadRequest as retry_exc:
            return _refresh_edit_outcome(retry_exc)
    except TelegramBadRequest as exc:
        return _refresh_edit_outcome(exc)
    return True


def _refresh_edit_outcome(exc: TelegramBadRequest) -> bool:
    """Map a failed refresh edit to "card alive" (``True``) / "gone" (``False``).

    ``message is not modified`` means the card is still there with identical
    content, so the loop keeps going. An edit-unavailable error means the card is
    gone and the loop should stop. Anything else is unexpected and re-raised.
    """
    if _is_message_not_modified(exc):
        return True
    if _is_edit_unavailable(exc):
        return False
    raise exc


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
