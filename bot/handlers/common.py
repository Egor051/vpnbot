
import logging

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, User as TgUser

from bot.container import Services
from bot.formatters import main_menu_text
from bot.keyboards.common import FAQ_PER_PAGE, FAQ_TOPICS, back_to_menu, faq_answer_keyboard, faq_keyboard, main_menu
from bot.messages import is_stale_callback_query_error, safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimitExceeded
from config.settings import SettingsError
from i18n import t
from models.dto import TelegramUserProfile
from models.enums import UserRole
from services.errors import AccessDenied, InvalidOperation, NotFound, ServiceError

router = Router()
logger = logging.getLogger(__name__)


def profile_from_tg(user: TgUser) -> TelegramUserProfile:
    """Build a TelegramUserProfile from an aiogram user object."""
    return TelegramUserProfile(
        telegram_user_id=user.id,
        username=user.username,
        first_name=user.first_name,
    )


async def is_admin(services: Services, user_id: int) -> bool:
    """Return whether the given user is a superadmin."""
    try:
        user = await services.users.get_user(user_id)
    except NotFound:
        return False
    return user.role == UserRole.SUPERADMIN


class InvalidCallbackData(ValueError):
    """Raised when a callback payload cannot be parsed; shown to the user verbatim."""


def parse_int_callback(value: str) -> int | None:
    """Parse an integer from a callback suffix; returns None instead of raising."""
    try:
        return int(value)
    except (ValueError, OverflowError):
        return None


_SAFE_EXCEPTIONS = (
    AccessDenied,
    InvalidOperation,
    NotFound,
    ServiceError,
    SettingsError,
    InvalidCallbackData,
    RateLimitExceeded,
)


def service_error_text(exc: Exception) -> str:
    """Return a user-safe message for the exception, hiding internal errors.

    When a service error carries an i18n ``key`` it is rendered in the actor's
    active locale; otherwise the exception's own (Russian) message is shown, so
    un-migrated raises degrade to the pre-i18n behaviour rather than leaking a
    raw identifier or an internal error.
    """
    if isinstance(exc, _SAFE_EXCEPTIONS):
        key = getattr(exc, "key", None)
        if key:
            params = getattr(exc, "params", None) or {}
            return t(key, **params)
        return str(exc)
    return t("internal_error")


async def answer_callback_error(callback: CallbackQuery, exc: Exception) -> None:
    """Show an error alert for a failed callback, logging unexpected errors."""
    if is_stale_callback_query_error(exc):
        logger.debug("Ignoring stale callback query error while handling callback: %s", exc)
        return
    if not isinstance(exc, _SAFE_EXCEPTIONS):
        logger.exception("Unhandled callback error")
    await safe_callback_answer(callback, service_error_text(exc), show_alert=True)


async def answer_message_error(message: Message, exc: Exception) -> None:
    """Reply with an error message for a failed message handler, logging unexpected errors."""
    if not isinstance(exc, _SAFE_EXCEPTIONS):
        logger.exception("Unhandled message error")
    await message.answer(service_error_text(exc), reply_markup=back_to_menu())


def _faq_page_title(page: int) -> str:
    total = (len(FAQ_TOPICS) + FAQ_PER_PAGE - 1) // FAQ_PER_PAGE
    return t("faq_page_title").format(page=page, total=total)


@router.message(Command("help"))
async def help_command(message: Message, services: Services) -> None:
    """Handle the /help command by showing the FAQ list."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    await message.answer(_faq_page_title(1), reply_markup=faq_keyboard(1))


@router.message(Command("faq"))
async def faq_command(message: Message, services: Services) -> None:
    """Handle the /faq command by showing the FAQ list."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    await message.answer(_faq_page_title(1), reply_markup=faq_keyboard(1))


@router.callback_query(F.data == "help")
async def help_callback(callback: CallbackQuery, services: Services) -> None:
    """Show the FAQ list in response to the help button."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.message and callback.from_user:
        await safe_edit_message_text(callback.message, _faq_page_title(1), reply_markup=faq_keyboard(1))


@router.callback_query(F.data == "noop")
async def noop_callback(callback: CallbackQuery) -> None:
    """Acknowledge a no-op callback without changing anything."""
    await safe_callback_answer(callback)


@router.callback_query(F.data.startswith("faq_page:"))
async def faq_page_callback(callback: CallbackQuery) -> None:
    """Show the requested page of the FAQ list."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.message is None or callback.data is None:
        return
    try:
        page = int(callback.data.split(":", 1)[1])
    except (ValueError, IndexError):
        page = 1
    total = (len(FAQ_TOPICS) + FAQ_PER_PAGE - 1) // FAQ_PER_PAGE
    page = max(1, min(page, total))
    await safe_edit_message_text(callback.message, _faq_page_title(page), reply_markup=faq_keyboard(page))


@router.callback_query(F.data.startswith("faq:"))
async def faq_answer_callback(callback: CallbackQuery) -> None:
    """Show the answer for the selected FAQ topic."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.message is None or callback.data is None:
        return
    parts = callback.data.split(":")
    topic = parts[1] if len(parts) > 1 else ""
    try:
        page = int(parts[2]) if len(parts) > 2 else 1
    except ValueError:
        page = 1
    valid_topics = {key for key, _ in FAQ_TOPICS}
    text = t(f"faq_{topic}") if topic in valid_topics else t("faq_not_found")
    await safe_edit_message_text(callback.message, text, reply_markup=faq_answer_keyboard(page))


@router.message(Command("menu"))
async def menu_command(message: Message, services: Services) -> None:
    """Handle the /menu command by showing the main menu."""
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
    """Show the main menu in response to the menu button."""
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
    """Handle the /cancel command by clearing the current FSM state."""
    if not await ensure_private_message(message):
        return
    await state.clear()
    await message.answer(t("cancel_done"), reply_markup=back_to_menu())
