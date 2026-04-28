from __future__ import annotations

import logging
from typing import Any

from aiogram import Bot, Router
from aiogram.filters import CommandStart
from aiogram.types import Message

from bot.middlewares.access import BLOCKED_START_TEXT
from bot.handlers.common import answer_message_error, is_admin, profile_from_tg
from bot.formatters import main_menu_text
from bot.keyboards.admin import access_request_keyboard
from bot.keyboards.common import main_reply_keyboard
from models.access import is_blocked_user
from models.enums import UserRole
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


@router.message(CommandStart())
async def start_command(message: Message, services: Any, bot: Bot) -> None:
    if message.from_user is None:
        return
    try:
        profile = profile_from_tg(message.from_user)
        result = await services.access.create_or_get_request(profile)
        if is_blocked_user(result.user):
            await message.answer(BLOCKED_START_TEXT)
            if result.request is None:
                await message.answer("Повторная заявка пока не создана. Дождитесь решения администратора.")
                return
            if result.created:
                await message.answer("Повторная заявка на доступ создана. Дождитесь решения администратора.")
                await _notify_admins(services, bot, result.request.id, profile.telegram_user_id, profile.username)
            else:
                await message.answer("Ваша повторная заявка уже ожидает решения администратора.")
            return
        if result.user.role in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            await message.answer(
                main_menu_text(message.from_user),
                reply_markup=main_reply_keyboard(await is_admin(services, message.from_user.id)),
            )
            return

        if result.request is None:
            await message.answer("Заявка уже обработана. Дождитесь решения администратора.")
            return

        if result.created:
            await message.answer("Заявка на доступ создана. Дождитесь решения администратора.")
            await _notify_admins(services, bot, result.request.id, profile.telegram_user_id, profile.username)
        else:
            await message.answer("Ваша заявка уже ожидает решения администратора.")
    except Exception as exc:
        await answer_message_error(message, exc)


async def _notify_admins(services: Any, bot: Bot, request_id: int, user_id: int, username: str | None) -> None:
    text = (
        "<b>Новая заявка на доступ</b>\n"
        f"Telegram ID: <code>{user_id}</code>\n"
        f"Username: {h('@' + username if username else 'не указан')}\n"
        f"Заявка: #{request_id}"
    )
    for admin_id in services.settings.admin_ids:
        try:
            await bot.send_message(admin_id, text, reply_markup=access_request_keyboard(request_id))
        except Exception:
            logger.warning("Не удалось отправить уведомление админу %s", admin_id, exc_info=True)
