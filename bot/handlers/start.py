
import logging

from aiogram import Bot, Router
from aiogram.filters import CommandStart
from aiogram.types import Message

from bot.container import Services
from bot.formatters import key_detail_text, main_menu_text
from bot.handlers.common import answer_message_error, is_admin, profile_from_tg
from bot.keyboards.admin import access_request_keyboard
from bot.keyboards.common import main_menu
from bot.keyboards.keys import request_trial_keyboard, trial_key_show_keyboard
from bot.private_chat import ensure_private_message
from bot.rate_limit import RateLimiter
from i18n import t
from models.access import is_blocked_user
from models.enums import UserRole
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


@router.message(CommandStart())
async def start_command(message: Message, services: Services, bot: Bot, rate_limiter: RateLimiter | None = None) -> None:
    """Handle the /start command and register or greet the user."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        if rate_limiter is not None:
            rate_limiter.check(message.from_user.id, "start", 20)
        profile = profile_from_tg(message.from_user)
        result = await services.access.create_or_get_request(profile)
        if is_blocked_user(result.user):
            if result.request is None:
                await message.answer(t("blocked_no_request"))
                return
            if result.created:
                await message.answer(t("blocked_request_created"))
                await _notify_admins(services, bot, result.request.id, profile.telegram_user_id, profile.username)
            else:
                await message.answer(t("blocked_request_pending"))
            await _send_trial_offer(message, services, profile.telegram_user_id)
            return
        if result.user.role in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            await message.answer(
                main_menu_text(message.from_user),
                reply_markup=main_menu(await is_admin(services, message.from_user.id)),
            )
            return

        if result.request is None:
            await message.answer(t("request_already_processed"))
        elif result.created:
            await message.answer(t("request_created"))
            await _notify_admins(services, bot, result.request.id, profile.telegram_user_id, profile.username)
        else:
            await message.answer(t("request_pending"))

        await _send_trial_offer(message, services, profile.telegram_user_id)
    except Exception as exc:
        await answer_message_error(message, exc)


async def _send_trial_offer(message: Message, services: Services, user_id: int) -> None:
    trial_keys = await services.vpn_keys.list_active_trial_by_owner(user_id)
    if trial_keys:
        key = trial_keys[0]
        await message.answer(
            t("trial_key_active", key_text=key_detail_text(key, viewer_user_id=user_id)),
            reply_markup=trial_key_show_keyboard(key.id),
        )
    elif await services.trial_access.can_request_trial(user_id):
        await message.answer(t("trial_offer"), reply_markup=request_trial_keyboard())


async def _notify_admins(services: Services, bot: Bot, request_id: int, user_id: int, username: str | None) -> None:
    text = t(
        "notify_admin_new_request",
        user_id=user_id,
        username=h("@" + username if username else t("not_specified")),
        request_id=request_id,
    )
    for admin_id in services.settings.admin_ids:
        try:
            await bot.send_message(admin_id, text, reply_markup=access_request_keyboard(request_id))
        except Exception:
            logger.warning("Failed to notify admin %s", admin_id, exc_info=True)
