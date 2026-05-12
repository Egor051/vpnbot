
from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from bot.keyboards.common import back_to_menu
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback

router = Router()


@router.callback_query(lambda callback: callback.data == "cancel")
async def cancel_callback(callback: CallbackQuery, state: FSMContext) -> None:
    if not await ensure_private_callback(callback):
        return
    await state.clear()
    await safe_callback_answer(callback, "Отменено")
    if callback.message:
        await safe_edit_message_text(callback.message, "Операция отменена.", reply_markup=back_to_menu())


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    await safe_callback_answer(callback, "Действие недоступно или устарело.", show_alert=True)
