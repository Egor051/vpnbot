
import logging

from aiogram import F, Router
from aiogram.types import CallbackQuery

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error
from bot.keyboards.admin_modules import (
    module_disable_confirm1_keyboard,
    module_disable_confirm2_keyboard,
    module_enable_confirm_keyboard,
    modules_back_keyboard,
    modules_panel_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY, PROTOCOL_NAMES

router = Router()
logger = logging.getLogger(__name__)


@router.callback_query(F.data == "admin:modules")
async def admin_modules_panel(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("modules_panel_title"),
            reply_markup=modules_panel_keyboard(modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z]+$"))
async def admin_module_disable_step1(callback: CallbackQuery, services: Services) -> None:
    """First disable confirmation step."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_disable_confirm1", label=label),
            reply_markup=module_disable_confirm1_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z]+:2$"))
async def admin_module_disable_step2(callback: CallbackQuery, services: Services) -> None:
    """Second disable confirmation step."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_disable_confirm2", label=label),
            reply_markup=module_disable_confirm2_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z]+:exec$"))
async def admin_module_disable_exec(callback: CallbackQuery, services: Services) -> None:
    """Execute protocol disable: delete all data and mark as disabled."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("module_disabling"))
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        deleted = await services.modules.disable_protocol(name, callback.from_user.id)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("module_disabled_ok", label=label, deleted=deleted),
            reply_markup=modules_panel_keyboard(modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:enable:[a-z]+$"))
async def admin_module_enable_confirm(callback: CallbackQuery, services: Services) -> None:
    """Show enable confirmation."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_enable_confirm", label=label),
            reply_markup=module_enable_confirm_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:enable:[a-z]+:exec$"))
async def admin_module_enable_exec(callback: CallbackQuery, services: Services) -> None:
    """Execute protocol enable."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("module_enabling"))
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await services.modules.enable_protocol(name, callback.from_user.id)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("module_enabled_ok", label=label),
            reply_markup=modules_panel_keyboard(modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)
