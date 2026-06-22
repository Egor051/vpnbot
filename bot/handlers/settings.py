
import logging

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

import i18n
from bot.container import Services
from bot.formatters import personal_cabinet_text, settings_intro_text
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.settings import personal_cabinet_keyboard, settings_menu_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from i18n import t
from models.dto import User
from models.enums import ProxyAccessStatus

router = Router()
logger = logging.getLogger(__name__)


def _settings_keyboard(user: User) -> InlineKeyboardMarkup:
    return settings_menu_keyboard(expiry_notifications_enabled=user.expiry_notifications_enabled)


async def _build_cabinet_text(services: Services, user: User) -> str:
    active_xray, active_awg, downloaded, uploaded = await services.vpn_keys.personal_summary_for_actor(
        user.telegram_user_id
    )
    proxy_stats = await services.proxy.get_user_proxy_stats(user.telegram_user_id)
    proxy_count = sum(1 for access in proxy_stats.accesses if access.status == ProxyAccessStatus.ACTIVE)
    return personal_cabinet_text(
        user,
        active_xray=active_xray,
        active_awg=active_awg,
        downloaded_bytes=downloaded,
        uploaded_bytes=uploaded,
        proxy_count=proxy_count,
    )


@router.message(Command("settings"))
async def settings_command(message: Message, services: Services) -> None:
    """Handle the /settings command by showing the settings panel."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        user = await services.users.require_approved_or_admin(message.from_user.id)
        await message.answer(settings_intro_text(), reply_markup=_settings_keyboard(user))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "settings:open")
async def settings_open_callback(callback: CallbackQuery, services: Services) -> None:
    """Show the settings panel: explanations on top, toggles/cabinet below."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        user = await services.users.require_approved_or_admin(callback.from_user.id)
        await safe_edit_message_text(callback.message, settings_intro_text(), reply_markup=_settings_keyboard(user))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "settings:cabinet")
async def settings_cabinet_callback(callback: CallbackQuery, services: Services) -> None:
    """Show the personal cabinet: profile plus a personal summary."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        user = await services.users.require_approved_or_admin(callback.from_user.id)
        text = await _build_cabinet_text(services, user)
        await safe_edit_message_text(callback.message, text, reply_markup=personal_cabinet_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "settings:lang:toggle")
async def settings_language_toggle(callback: CallbackQuery, services: Services) -> None:
    """Flip the user's interface language between ru and en, then re-render."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        await safe_callback_answer(callback)
        return
    try:
        new_language = "en" if i18n.resolve_locale() == "ru" else "ru"
        user = await services.users.set_language(callback.from_user.id, new_language)
        # Apply for the current render so the panel is shown in the new language.
        i18n.set_locale(new_language)
        await safe_callback_answer(callback, t("settings_language_changed"))
        await safe_edit_message_text(callback.message, settings_intro_text(), reply_markup=_settings_keyboard(user))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "settings:notify:toggle")
async def settings_notifications_toggle(callback: CallbackQuery, services: Services) -> None:
    """Toggle the user's expiry-reminder opt-out, then re-render the panel."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        await safe_callback_answer(callback)
        return
    try:
        current = await services.users.get_user(callback.from_user.id)
        new_enabled = not current.expiry_notifications_enabled
        user = await services.users.set_expiry_notifications(callback.from_user.id, new_enabled)
        toast = t("settings_notifications_on") if new_enabled else t("settings_notifications_off")
        await safe_callback_answer(callback, toast)
        await safe_edit_message_text(callback.message, settings_intro_text(), reply_markup=_settings_keyboard(user))
    except Exception as exc:
        await answer_callback_error(callback, exc)
