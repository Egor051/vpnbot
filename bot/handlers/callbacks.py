
from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from bot.keyboards.admin import admin_panel_keyboard
from bot.keyboards.common import back_to_menu
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from i18n import t

router = Router()


@router.callback_query(lambda callback: callback.data == "cancel")
async def cancel_callback(callback: CallbackQuery, state: FSMContext) -> None:
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    cancel_target = data.get("cancel_target", "menu:main")
    await state.clear()
    await safe_callback_answer(callback, t("cancel_done"))
    if callback.message:
        if cancel_target == "admin:panel":
            await safe_edit_message_text(callback.message, t("admin_panel_title"), reply_markup=admin_panel_keyboard())
        else:
            await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback, t("action_stale"), show_alert=True)
