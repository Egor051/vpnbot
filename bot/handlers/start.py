
import logging

from aiogram import Bot, Router
from aiogram.enums import ChatType
from aiogram.filters import CommandObject, CommandStart
from aiogram.types import Message

from bot.commands import publish_admin_commands
from bot.container import Services
from bot.formatters import key_detail_text, main_menu_text
from bot.handlers.common import answer_message_error, main_menu_markup, profile_from_tg
from bot.keyboards.admin import access_request_keyboard
from bot.keyboards.keys import request_trial_keyboard, trial_key_show_keyboard
from bot.private_chat import ensure_private_message
from bot.rate_limit import RateLimiter
from i18n import t
from models.access import is_blocked_user
from models.dto import TelegramUserProfile
from models.enums import UserRole
from services.superadmin_claim import ClaimOutcome, claim_payload
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


@router.message(CommandStart())
async def start_command(
    message: Message,
    services: Services,
    bot: Bot,
    rate_limiter: RateLimiter | None = None,
    command: CommandObject | None = None,
) -> None:
    """Handle the /start command and register or greet the user."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        if rate_limiter is not None:
            rate_limiter.check(message.from_user.id, "start", 20)
        profile = profile_from_tg(message.from_user)
        # /start claim_<code>: the install deep link that makes the first superadmin
        # (services/superadmin_claim.py). Handled before anything else, and never
        # falls through to an access request.
        claim_code = claim_payload(command.args if command is not None else None)
        if claim_code is not None and services.superadmin_claim is not None:
            await _claim_superadmin(message, services, bot, profile, claim_code)
            return
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
            return
        # A moderator has access too: before, /start filed an access request for
        # them (see AccessApprovalService.create_or_get_request) and showed no menu.
        if result.user.role in {UserRole.SUPERADMIN, UserRole.MODERATOR, UserRole.APPROVED_USER}:
            await message.answer(
                main_menu_text(message.from_user),
                reply_markup=await main_menu_markup(services, message.from_user.id),
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


async def _claim_superadmin(
    message: Message, services: Services, bot: Bot, profile: TelegramUserProfile, code: str
) -> None:
    assert services.superadmin_claim is not None
    outcome = await services.superadmin_claim.claim(
        profile, code, private_chat=message.chat.type == ChatType.PRIVATE
    )
    if outcome is not ClaimOutcome.CLAIMED:
        # One answer for every failure — wrong, expired, consumed, inert, rate
        # limited. The reason is in the bot log, never in the chat.
        await message.answer(t("superadmin_claim_failed"))
        return
    await publish_admin_commands(bot, services.settings, profile.telegram_user_id)
    await message.answer(t("superadmin_claim_success"))
    if message.from_user is not None:
        await message.answer(
            main_menu_text(message.from_user),
            reply_markup=await main_menu_markup(services, profile.telegram_user_id),
        )


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
