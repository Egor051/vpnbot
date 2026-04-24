from __future__ import annotations

from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from bot.keyboards.common import back_to_menu

router = Router()


@router.callback_query(lambda callback: callback.data == "cancel")
async def cancel_callback(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer("Отменено")
    if callback.message:
        await callback.message.answer("Операция отменена.", reply_markup=back_to_menu())


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    await callback.answer("Действие недоступно или устарело.", show_alert=True)
