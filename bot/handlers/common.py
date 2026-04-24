from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, User as TgUser

from bot.formatters import role_text
from bot.keyboards.common import back_to_menu, main_menu
from bot.messages import safe_edit_message_text
from bot.rate_limit import RateLimitExceeded
from config.settings import SettingsError
from models.dto import TelegramUserProfile
from models.enums import UserRole
from services.errors import AccessDenied, InvalidOperation, NotFound, ServiceError
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


def profile_from_tg(user: TgUser) -> TelegramUserProfile:
    return TelegramUserProfile(
        telegram_user_id=user.id,
        username=user.username,
        first_name=user.first_name,
    )


async def is_admin(services: Any, user_id: int) -> bool:
    try:
        user = await services.users.get_user(user_id)
    except NotFound:
        return False
    return user.role == UserRole.SUPERADMIN


def service_error_text(exc: Exception) -> str:
    if isinstance(exc, (AccessDenied, InvalidOperation, NotFound, ServiceError, SettingsError, ValueError, RateLimitExceeded)):
        return str(exc)
    return "Произошла внутренняя ошибка. Попробуйте позже."


async def answer_callback_error(callback: CallbackQuery, exc: Exception) -> None:
    if not isinstance(exc, (AccessDenied, InvalidOperation, NotFound, ServiceError, SettingsError, ValueError, RateLimitExceeded)):
        logger.exception("Unhandled callback error")
    await callback.answer(service_error_text(exc), show_alert=True)


async def answer_message_error(message: Message, exc: Exception) -> None:
    if not isinstance(exc, (AccessDenied, InvalidOperation, NotFound, ServiceError, SettingsError, ValueError, RateLimitExceeded)):
        logger.exception("Unhandled message error")
    await message.answer(service_error_text(exc), reply_markup=back_to_menu())


async def help_text(services: Any, user_id: int) -> str:
    try:
        user = await services.users.get_user(user_id)
    except NotFound:
        return "Отправьте /start, чтобы создать заявку на доступ."
    if user.role == UserRole.BLOCKED_USER:
        return "Ваш доступ ограничен."
    if user.role == UserRole.PENDING_USER:
        return "Ваша заявка ожидает решения администратора."
    lines = [
        f"Ваша роль: {role_text(user.role)}",
        "",
        "Доступные разделы:",
        "• Мои ключи",
        "• Создать ключ",
        "• Прокси",
    ]
    if user.role == UserRole.SUPERADMIN:
        lines.append("• Админ-панель")
    lines.append("")
    lines.append("Опасные действия требуют подтверждения.")
    return "\n".join(lines)


@router.message(Command("help"))
async def help_command(message: Message, services: Any) -> None:
    if message.from_user is None:
        return
    await message.answer(await help_text(services, message.from_user.id), reply_markup=back_to_menu())


@router.callback_query(F.data == "help")
async def help_callback(callback: CallbackQuery, services: Any) -> None:
    await callback.answer()
    if callback.message and callback.from_user:
        await safe_edit_message_text(callback.message, await help_text(services, callback.from_user.id), reply_markup=back_to_menu())


@router.message(F.text == "Помощь")
async def help_menu_message(message: Message, services: Any) -> None:
    if message.from_user is None:
        return
    await message.answer(await help_text(services, message.from_user.id), reply_markup=back_to_menu())


@router.callback_query(F.data == "menu:main")
async def menu_callback(callback: CallbackQuery, services: Any) -> None:
    await callback.answer()
    if callback.from_user is None or callback.message is None:
        return
    await safe_edit_message_text(
        callback.message,
        f"Главное меню, {h(callback.from_user.first_name or callback.from_user.id)}.",
        reply_markup=main_menu(await is_admin(services, callback.from_user.id)),
    )


@router.message(Command("cancel"))
async def cancel_command(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Операция отменена.", reply_markup=back_to_menu())
