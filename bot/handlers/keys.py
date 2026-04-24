from __future__ import annotations

from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import (
    create_confirm_text,
    key_detail_text,
    keys_page_text,
    note_confirm_text,
    xray_config_text,
)
from bot.fsm.states import CreateKeyStates, EditNoteStates
from bot.handlers.common import answer_callback_error, answer_message_error, profile_from_tg
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.keys import (
    confirm_keyboard,
    create_key_keyboard,
    key_actions_keyboard,
    keys_list_keyboard,
)
from bot.messages import AWG_CONFIG_FILENAME, safe_edit_message_text, send_awg_config
from bot.pagination import page_offset, split_page
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimiter
from models.enums import VpnKeyType

router = Router()
KEYS_PAGE_SIZE = 5


@router.callback_query(F.data.regexp(r"^keys:list(?::\d+)?$"))
async def list_keys(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data, default=0)
    try:
        items = await services.vpn_keys.list_for_actor(
            callback.from_user.id,
            limit=KEYS_PAGE_SIZE + 1,
            offset=page_offset(page, KEYS_PAGE_SIZE),
        )
        keys, has_next = split_page(items, KEYS_PAGE_SIZE)
        text = keys_page_text(keys, page)
        await safe_edit_message_text(callback.message, text, reply_markup=keys_list_keyboard(keys, page=page, has_next=has_next))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(F.text == "Мои ключи")
async def list_keys_message(message: Message, services: Any) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        items = await services.vpn_keys.list_for_actor(message.from_user.id, limit=KEYS_PAGE_SIZE + 1)
        keys, has_next = split_page(items, KEYS_PAGE_SIZE)
        await message.answer(keys_page_text(keys, 0), reply_markup=keys_list_keyboard(keys, page=0, has_next=has_next))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "keys:create")
async def create_key_menu(callback: CallbackQuery) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.message:
        await safe_edit_message_text(callback.message, "Выберите тип ключа:", reply_markup=create_key_keyboard())


@router.message(F.text == "Создать ключ")
async def create_key_menu_message(message: Message) -> None:
    if not await ensure_private_message(message):
        return
    await message.answer("Выберите тип ключа:", reply_markup=create_key_keyboard())


@router.callback_query(F.data.in_({"keys:create:xray", "keys:create:awg"}))
async def create_key_choose(callback: CallbackQuery, state: FSMContext) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.message is None or callback.data is None:
        return
    key_type = callback.data.rsplit(":", 1)[-1]
    await state.set_state(CreateKeyStates.waiting_note)
    await state.update_data(key_type=key_type)
    await safe_edit_message_text(
        callback.message,
        "Введите заметку для ключа или отправьте <code>-</code>, чтобы оставить пустой.",
        reply_markup=cancel_keyboard(),
    )


@router.message(CreateKeyStates.waiting_note)
async def create_key_note(message: Message, state: FSMContext) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    data = await state.get_data()
    key_type = str(data.get("key_type") or "")
    note = _clean_note(message.text)
    await state.update_data(note=note)
    await state.set_state(CreateKeyStates.confirming)
    await message.answer(
        create_confirm_text(key_type, note),
        reply_markup=confirm_cancel_keyboard("create:confirm"),
    )


@router.callback_query(CreateKeyStates.confirming, F.data == "create:confirm")
async def create_key_confirm(callback: CallbackQuery, state: FSMContext, services: Any, rate_limiter: RateLimiter) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    await state.clear()
    key_type = str(data.get("key_type") or "")
    note = data.get("note")
    try:
        profile = profile_from_tg(callback.from_user)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        await callback.answer("Создаю ключ...")
        if key_type == VpnKeyType.XRAY.value:
            result = await services.xray.create_xray_key(callback.from_user.id, profile, note)
        elif key_type == VpnKeyType.AWG.value:
            result = await services.awg.create_awg_key(callback.from_user.id, profile, note)
        else:
            await safe_edit_message_text(callback.message, "Неизвестный тип ключа.")
            return
        if result.key.key_type == VpnKeyType.AWG:
            config = await services.awg.get_awg_client_config_plain(callback.from_user.id, result.key.id, audit=False)
            await send_awg_config(
                callback.message,
                title=f"AWG-ключ #{result.key.id}",
                config_text=config,
                filename=AWG_CONFIG_FILENAME,
                reply_markup=key_actions_keyboard(result.key),
                edit_text=True,
            )
        else:
            await safe_edit_message_text(callback.message, result.config_text, reply_markup=key_actions_keyboard(result.key))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:open:"))
async def open_key(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(callback.message, key_detail_text(key), reply_markup=key_actions_keyboard(key))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:show:"))
async def show_key_config(callback: CallbackQuery, services: Any, rate_limiter: RateLimiter) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        rate_limiter.check(callback.from_user.id, "key_show", 5)
        await callback.answer()
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if key.key_type == VpnKeyType.XRAY:
            text = xray_config_text(await services.xray.get_xray_key_config(callback.from_user.id, key_id))
            await safe_edit_message_text(callback.message, text, reply_markup=key_actions_keyboard(key))
        else:
            config = await services.awg.get_awg_client_config_plain(callback.from_user.id, key_id)
            await send_awg_config(
                callback.message,
                title=f"AWG-ключ #{key.id}",
                config_text=config,
                filename=AWG_CONFIG_FILENAME,
                reply_markup=key_actions_keyboard(key),
                edit_text=True,
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:revoke:"))
async def revoke_key_prompt(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            f"Отозвать ключ #{key_id}? Доступ по нему будет отключён.",
            reply_markup=confirm_keyboard("revoke", key_id),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:delete:"))
async def delete_key_prompt(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            f"Удалить ключ #{key_id}? Это мягкое удаление через сервис.",
            reply_markup=confirm_keyboard("delete", key_id),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("confirm:"))
async def confirm_key_action(callback: CallbackQuery, services: Any, rate_limiter: RateLimiter) -> None:
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    if not await ensure_private_callback(callback):
        return
    try:
        _, action, raw_key_id = callback.data.split(":", 2)
        key_id = int(raw_key_id)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if action == "revoke":
            rate_limiter.check(callback.from_user.id, "key_revoke", 10)
            await callback.answer("Выполняю...")
            updated = (
                await services.xray.revoke_xray_key(callback.from_user.id, key_id)
                if key.key_type == VpnKeyType.XRAY
                else await services.awg.revoke_awg_key(callback.from_user.id, key_id)
            )
            await safe_edit_message_text(callback.message, "Ключ отозван.", reply_markup=key_actions_keyboard(updated))
        elif action == "delete":
            rate_limiter.check(callback.from_user.id, "key_delete", 10)
            await callback.answer("Выполняю...")
            updated = (
                await services.xray.delete_xray_key(callback.from_user.id, key_id)
                if key.key_type == VpnKeyType.XRAY
                else await services.awg.delete_awg_key(callback.from_user.id, key_id)
            )
            await safe_edit_message_text(callback.message, "Ключ удалён.", reply_markup=key_actions_keyboard(updated))
        else:
            await callback.answer("Неизвестное действие", show_alert=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:note:"))
async def edit_note_prompt(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await callback.answer()
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await state.set_state(EditNoteStates.waiting_note)
        await state.update_data(key_id=key_id)
        await safe_edit_message_text(
            callback.message,
            f"Новая заметка для {key.key_type.value.upper()} #{key.id}. Отправьте <code>-</code>, чтобы очистить.",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(EditNoteStates.waiting_note)
async def edit_note_waiting(message: Message, state: FSMContext, services: Any) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    data = await state.get_data()
    try:
        key_id = int(data["key_id"])
        key = await services.vpn_keys.get_for_actor(message.from_user.id, key_id)
        note = _clean_note(message.text)
        await state.update_data(note=note)
        await state.set_state(EditNoteStates.confirming)
        await message.answer(note_confirm_text(key, note), reply_markup=confirm_cancel_keyboard("note:confirm"))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(EditNoteStates.confirming, F.data == "note:confirm")
async def edit_note_confirm(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    await callback.answer("Сохраняю...")
    data = await state.get_data()
    await state.clear()
    try:
        key_id = int(data["key_id"])
        note = data.get("note")
        await services.notes.update_key_note(callback.from_user.id, key_id, note)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(callback.message, "Заметка обновлена.", reply_markup=key_actions_keyboard(key))
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _clean_note(value: str | None) -> str | None:
    if value is None:
        return None
    note = value.strip()
    return None if note in {"", "-"} else note


def _page_from_callback(data: str | None, default: int = 0) -> int:
    if not data:
        return default
    parts = data.split(":")
    if parts and parts[-1].isdigit():
        return max(int(parts[-1]), 0)
    return default
