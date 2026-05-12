from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, User as TgUser

from bot.container import Services
from bot.formatters import main_menu_text
from bot.keyboards.common import back_to_menu, faq_answer_keyboard, faq_keyboard, main_menu
from bot.messages import is_stale_callback_query_error, safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimitExceeded
from config.settings import SettingsError
from models.dto import TelegramUserProfile
from models.enums import UserRole
from services.errors import AccessDenied, InvalidOperation, NotFound, ServiceError

router = Router()
logger = logging.getLogger(__name__)


def profile_from_tg(user: TgUser) -> TelegramUserProfile:
    return TelegramUserProfile(
        telegram_user_id=user.id,
        username=user.username,
        first_name=user.first_name,
    )


async def is_admin(services: Services, user_id: int) -> bool:
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
    if is_stale_callback_query_error(exc):
        logger.debug("Ignoring stale callback query error while handling callback: %s", exc)
        return
    if not isinstance(exc, (AccessDenied, InvalidOperation, NotFound, ServiceError, SettingsError, ValueError, RateLimitExceeded)):
        logger.exception("Unhandled callback error")
    await safe_callback_answer(callback, service_error_text(exc), show_alert=True)


async def answer_message_error(message: Message, exc: Exception) -> None:
    if not isinstance(exc, (AccessDenied, InvalidOperation, NotFound, ServiceError, SettingsError, ValueError, RateLimitExceeded)):
        logger.exception("Unhandled message error")
    await message.answer(service_error_text(exc), reply_markup=back_to_menu())


FAQ_TEXT = "<b>Часто задаваемые вопросы</b>"

FAQ_ANSWERS = {
    "connect": (
        "После создания ключа бот выдаст конфигурацию. Скопируйте её в подходящее VPN-приложение "
        "или импортируйте файл, если он доступен. Для AWG обычно используется конфиг .conf, "
        "для Xray — ссылка/профиль. После импорта включите подключение в приложении."
    ),
    "device": (
        "Да. Один ключ рассчитан на одно устройство. Если использовать один и тот же ключ на нескольких "
        "устройствах, подключение может работать нестабильно, а статистика и управление доступом будут путаться."
    ),
    "choice": "Если не знаете, что выбрать, начните с XRay.",
    "trouble": (
        "Проверьте интернет, правильность импортированного профиля, дату окончания доступа и не используется ли "
        "этот же ключ на другом устройстве. Также попробуйте выключить и включить VPN-приложение. Если и это не "
        "помогло, попробуйте включить и выключить \"режим самолета\" или перезагрузить устройство. Если проблема "
        "осталась — напишите в техподдержку."
    ),
    "notes": "Нет. Ваши заметки никто не видит.",
    "support": "Техподдержка: @ktotakmoje",
}


@router.message(Command("help"))
async def help_command(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    await message.answer(FAQ_TEXT, reply_markup=faq_keyboard())


@router.message(Command("faq"))
async def faq_command(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    await message.answer(FAQ_TEXT, reply_markup=faq_keyboard())


@router.callback_query(F.data == "help")
async def help_callback(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.message and callback.from_user:
        await safe_edit_message_text(callback.message, FAQ_TEXT, reply_markup=faq_keyboard())


@router.callback_query(F.data.startswith("faq:"))
async def faq_answer_callback(callback: CallbackQuery) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.message is None or callback.data is None:
        return
    topic = callback.data.split(":", 1)[1]
    text = FAQ_ANSWERS.get(topic)
    if text is None:
        text = "Ответ не найден."
    await safe_edit_message_text(callback.message, text, reply_markup=faq_answer_keyboard())


@router.message(F.text == "Помощь")
async def help_menu_message(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    await message.answer(FAQ_TEXT, reply_markup=faq_keyboard())


@router.message(Command("menu"))
async def menu_command(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        await services.users.require_approved_or_admin(message.from_user.id)
        await message.answer(
            main_menu_text(message.from_user),
            reply_markup=main_menu(await is_admin(services, message.from_user.id)),
        )
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "menu:main")
async def menu_callback(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await services.users.require_approved_or_admin(callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            main_menu_text(callback.from_user),
            reply_markup=main_menu(await is_admin(services, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(Command("cancel"))
async def cancel_command(message: Message, state: FSMContext) -> None:
    if not await ensure_private_message(message):
        return
    await state.clear()
    await message.answer("Операция отменена.", reply_markup=back_to_menu())
