
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
from bot.rate_limit import RateLimiter, RateLimitExceeded
from config.settings import SettingsError
from i18n import t
from models.dto import KeyTrafficStatsView, TelegramUserProfile, VpnKey
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


# Cooldown between two live backend samples for the same viewer. Traffic is now
# printed on the key/subscription screen itself instead of behind a button, so this
# runs on plain navigation: within the cooldown the screen falls back to the cached
# counters (at most one background-loop interval old) rather than refusing to open.
STATS_REFRESH_COOLDOWN_SECONDS = 5


def admin_owner_context(key: VpnKey, actor_user_id: int) -> int | None:
    """The ``owner_user_id`` a key screen must be rendered under, or None.

    Not None means "an admin is looking at somebody else's key", and every key
    screen has to know it: the keyboard then drops the owner-only actions (note,
    fingerprint) and its «to list» button goes back to that user's key list
    rather than the admin's own.

    It lives here, next to :func:`stats_views_for_screen`, because it is the same
    question asked by two modules. ``bot/handlers/callbacks.py`` used to skip it
    when re-rendering a key card after a cancel, so an admin who cancelled out of
    a wizard got the owner's keyboard on a foreign key — the same screen, reached
    two ways, offering two different sets of buttons.
    """
    return key.owner_user_id if key.owner_user_id != actor_user_id else None


async def stats_views_for_screen(
    services: Services,
    rate_limiter: RateLimiter,
    actor_user_id: int,
    keys: list[VpnKey],
) -> list[KeyTrafficStatsView] | None:
    """Traffic for the keys of one screen — live when allowed, cached otherwise.

    Returns ``None`` only when nothing at all could be read, which the callers
    render as "no figures yet" instead of as zeroes. A screen must never fail to
    open because a backend is down: this swallows the sampling error (already
    logged by the stats service) and degrades to whatever the database holds.
    """
    if not keys:
        return []
    try:
        rate_limiter.check(actor_user_id, "stats_refresh", STATS_REFRESH_COOLDOWN_SECONDS)
    except RateLimitExceeded:
        return await _cached_stats_views(services, keys)
    try:
        return await services.traffic_stats.refresh_views(keys)
    except Exception:
        logger.warning("Live traffic sample failed; falling back to cached figures", exc_info=True)
        return await _cached_stats_views(services, keys)


async def _cached_stats_views(services: Services, keys: list[VpnKey]) -> list[KeyTrafficStatsView] | None:
    try:
        cached = await services.traffic_stats.cached_for_keys(keys)
    except Exception:
        logger.warning("Cached traffic read failed", exc_info=True)
        return None
    return [KeyTrafficStatsView(key=key, owner=None, stats=cached.get(key.id)) for key in keys]


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
