from __future__ import annotations

from typing import Any

from aiogram import F, Router
from aiogram.types import CallbackQuery, Message

from bot.formatters import proxy_page_text
from bot.handlers.common import answer_callback_error
from bot.keyboards.common import pagination_keyboard
from bot.messages import safe_edit_message_text
from bot.pagination import page_offset, split_page
from bot.private_chat import ensure_private_callback, ensure_private_message

router = Router()
PROXY_PAGE_SIZE = 5


@router.message(F.text == "Прокси")
async def show_proxy_message(message: Message, services: Any) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        items = await services.proxy.list_available(message.from_user.id, limit=PROXY_PAGE_SIZE + 1)
        entries, has_next = split_page(items, PROXY_PAGE_SIZE)
        await message.answer(
            proxy_page_text(entries, 0),
            reply_markup=pagination_keyboard(
                prev_data=None,
                next_data="proxy:show:1" if has_next else None,
                back_data="menu:main",
            ),
        )
    except Exception as exc:
        from bot.handlers.common import answer_message_error

        await answer_message_error(message, exc)


@router.callback_query(F.data.regexp(r"^proxy:show(?::\d+)?$"))
async def show_proxy(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        items = await services.proxy.list_available(
            callback.from_user.id,
            limit=PROXY_PAGE_SIZE + 1,
            offset=page_offset(page, PROXY_PAGE_SIZE),
        )
        entries, has_next = split_page(items, PROXY_PAGE_SIZE)
        await safe_edit_message_text(
            callback.message,
            proxy_page_text(entries, page),
            reply_markup=pagination_keyboard(
                prev_data=f"proxy:show:{page - 1}" if page > 0 else None,
                next_data=f"proxy:show:{page + 1}" if has_next else None,
                back_data="menu:main",
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _page_from_callback(data: str | None) -> int:
    if not data:
        return 0
    last = data.split(":")[-1]
    return max(int(last), 0) if last.isdigit() else 0
