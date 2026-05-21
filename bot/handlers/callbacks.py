
from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from bot.container import Services
from bot.formatters import key_detail_text
from bot.keyboards.admin import admin_panel_keyboard
from bot.keyboards.common import back_to_menu
from bot.keyboards.keys import create_key_keyboard, key_actions_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from i18n import t

router = Router()


@router.callback_query(lambda callback: callback.data == "cancel")
async def cancel_callback(callback: CallbackQuery, state: FSMContext, services: Services | None = None) -> None:
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    cancel_target = data.get("cancel_target", "menu:main")
    await state.clear()
    await safe_callback_answer(callback, t("cancel_done"))
    if callback.message is None:
        return
    if cancel_target == "admin:panel":
        await safe_edit_message_text(callback.message, t("admin_panel_title"), reply_markup=admin_panel_keyboard())
    elif cancel_target == "keys:create":
        await safe_edit_message_text(
            callback.message,
            f"{t('one_key_one_device')}\n\n{t('choose_key_type')}",
            reply_markup=create_key_keyboard(),
        )
    elif cancel_target and cancel_target.startswith("key:open:"):
        try:
            key_id = int(cancel_target.rsplit(":", 1)[-1])
            user_id = callback.from_user.id if callback.from_user else None
            if user_id is None or services is None:
                raise ValueError
            key = await services.vpn_keys.get_for_actor(user_id, key_id)
            await safe_edit_message_text(
                callback.message,
                key_detail_text(key, viewer_user_id=user_id),
                reply_markup=key_actions_keyboard(key),
            )
        except Exception:
            await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())
    else:
        await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback, t("action_stale"), show_alert=True)
