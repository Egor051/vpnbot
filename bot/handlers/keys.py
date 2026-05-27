
from __future__ import annotations

from contextlib import suppress
from typing import Any

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import (
    awg_config_text,
    create_confirm_text,
    key_detail_text,
    keys_page_text,
    note_confirm_text,
    traffic_stats_text,
    xray_config_text,
)
from bot.container import Services
from bot.fsm.states import CreateKeyStates, EditNoteStates, TrialRequestStates
from bot.handlers.common import InvalidCallbackData, answer_callback_error, answer_message_error, parse_int_callback, profile_from_tg
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.keys import (
    after_key_deleted_keyboard,
    confirm_keyboard,
    create_key_keyboard,
    expiry_choice_keyboard,
    key_actions_keyboard,
    keys_list_keyboard,
    mtu_choice_keyboard,
    trial_protocol_keyboard,
)
from aiogram.types import BufferedInputFile
from bot.messages import awg_config_filename, safe_callback_answer, safe_edit_message_text
from bot.pagination import MAX_PAGE, page_offset
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimiter
from i18n import t
from models.enums import AuditEntityType, VpnKeyType
from services.errors import AccessDenied, NotFound

router = Router()
KEYS_PAGE_SIZE = 5


@router.callback_query(F.data.regexp(r"^keys:list(?::\d+)?$"))
async def list_keys(callback: CallbackQuery, services: Services) -> None:
    """Show the current user's key list page via callback."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data, default=0)
    try:
        keys, current_page, total_pages, has_next = await load_keys_page(
            services,
            callback.from_user.id,
            page=page,
            page_size=KEYS_PAGE_SIZE,
        )
        text = keys_page_text(keys, current_page, viewer_user_id=callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            text,
            reply_markup=keys_list_keyboard(keys, page=current_page, has_next=has_next, total_pages=total_pages),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(F.text == t("btn_my_keys"))
async def list_keys_message(message: Message, services: Services) -> None:
    """Show the current user's key list in response to the my-keys button."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        keys, current_page, total_pages, has_next = await load_keys_page(
            services,
            message.from_user.id,
            page=0,
            page_size=KEYS_PAGE_SIZE,
        )
        await message.answer(
            keys_page_text(keys, current_page, viewer_user_id=message.from_user.id),
            reply_markup=keys_list_keyboard(keys, page=current_page, has_next=has_next, total_pages=total_pages),
        )
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "keys:create")
async def create_key_menu(callback: CallbackQuery, services: Services) -> None:
    """Show the key type selection menu for creating a key."""
    if not await ensure_private_callback(callback):
        return
    try:
        if callback.from_user is None:
            return
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    if callback.message:
        await safe_edit_message_text(
            callback.message,
            f"{t('one_key_one_device')}\n\n{t('choose_key_type')}",
            reply_markup=create_key_keyboard(),
        )


@router.message(F.text == t("btn_create_key"))
async def create_key_menu_message(message: Message, services: Services) -> None:
    """Show the key type selection menu in response to the create-key button."""
    if not await ensure_private_message(message):
        return
    if message.from_user is None:
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        await message.answer(f"{t('one_key_one_device')}\n\n{t('choose_key_type')}", reply_markup=create_key_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.in_({"keys:create:xray", "keys:create:awg"}))
async def create_key_choose(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Record the chosen key type and prompt for a note."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
        key_type = callback.data.rsplit(":", 1)[-1]
        await state.set_state(CreateKeyStates.waiting_note)
        await state.update_data(key_type=key_type, cancel_target="keys:create", note_prompt_msg_id=callback.message.message_id)
        await safe_edit_message_text(
            callback.message,
            f"{t('note_create_warning')}\n\n{t('key_note_prompt')}",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(CreateKeyStates.waiting_note)
async def create_key_note(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """Store the entered note and advance to MTU or expiry selection."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        note = _clean_note(message.text)
        data = await state.get_data()
        key_type = str(data.get("key_type") or "")
        note_prompt_msg_id = data.get("note_prompt_msg_id")
        await state.update_data(note=note)
        if note_prompt_msg_id:
            with suppress(Exception):
                await bot.delete_message(chat_id=message.chat.id, message_id=note_prompt_msg_id)
        if key_type == VpnKeyType.AWG.value:
            await state.set_state(CreateKeyStates.waiting_mtu)
            await message.answer(t("mtu_prompt"), reply_markup=mtu_choice_keyboard())
        else:
            await state.set_state(CreateKeyStates.waiting_expiry)
            await message.answer(t("expiry_prompt"), reply_markup=expiry_choice_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(CreateKeyStates.waiting_mtu, F.data.regexp(r"^mtu:\d+$"))
async def create_key_mtu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Store the chosen MTU value and advance to expiry selection."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        raw = callback.data.split(":", 1)[1]
        mtu = int(raw)
        if mtu < 1 or mtu > 1500:
            await safe_callback_answer(callback, t("mtu_invalid"), show_alert=True)
            return
        await state.update_data(mtu=mtu)
        await state.set_state(CreateKeyStates.waiting_expiry)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            t("expiry_prompt"),
            reply_markup=expiry_choice_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(CreateKeyStates.waiting_mtu, F.data == "mtu:custom")
async def create_key_mtu_custom_request(callback: CallbackQuery, state: FSMContext) -> None:
    """Prompt the user to enter a custom MTU value."""
    if not await ensure_private_callback(callback):
        return
    if callback.message is None:
        return
    await safe_callback_answer(callback)
    await state.set_state(CreateKeyStates.waiting_mtu_custom)
    await state.update_data(mtu_prompt_msg_id=callback.message.message_id)
    await safe_edit_message_text(callback.message, t("mtu_custom_prompt"), reply_markup=cancel_keyboard())


@router.message(CreateKeyStates.waiting_mtu_custom)
async def create_key_mtu_custom(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """Validate the custom MTU input and advance to expiry selection."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        mtu = _parse_mtu(message.text or "")
        if mtu is None:
            await message.answer(t("mtu_enter_integer"))
            return
        data = await state.get_data()
        mtu_prompt_msg_id = data.get("mtu_prompt_msg_id")
        await state.update_data(mtu=mtu)
        if mtu_prompt_msg_id:
            with suppress(Exception):
                await bot.delete_message(chat_id=message.chat.id, message_id=mtu_prompt_msg_id)
        await state.set_state(CreateKeyStates.waiting_expiry)
        await message.answer(t("expiry_prompt"), reply_markup=expiry_choice_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(CreateKeyStates.waiting_expiry, F.data.regexp(r"^expiry:(permanent|\d+)$"))
async def create_key_expiry(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Store the chosen expiry and show the key creation confirmation."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        raw = callback.data.split(":", 1)[1]
        if raw == "permanent":
            expires_at = None
        else:
            days = int(raw)
            if days < 1 or days > services.settings.key_max_trial_days:
                await safe_callback_answer(callback, t("expiry_invalid", max=services.settings.key_max_trial_days), show_alert=True)
                return
            from datetime import datetime, timedelta, timezone
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()
        await state.update_data(expires_at=expires_at)
        await state.set_state(CreateKeyStates.confirming)
        await safe_callback_answer(callback)
        data = await state.get_data()
        key_type = str(data.get("key_type") or "")
        note = data.get("note")
        mtu = int(data["mtu"]) if data.get("mtu") is not None else None
        from bot.keyboards.common import confirm_cancel_keyboard
        await safe_edit_message_text(
            callback.message,
            create_confirm_text(key_type, note, expires_at=expires_at, mtu=mtu),
            reply_markup=confirm_cancel_keyboard("create:confirm"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(CreateKeyStates.waiting_expiry, F.data == "expiry:custom")
async def create_key_expiry_custom(callback: CallbackQuery, state: FSMContext) -> None:
    """Prompt the user to enter a custom number of expiry days."""
    if not await ensure_private_callback(callback):
        return
    if callback.message is None:
        return
    await safe_callback_answer(callback)
    await state.set_state(CreateKeyStates.waiting_custom_days)
    await safe_edit_message_text(
        callback.message,
        t("expiry_custom_prompt"),
        reply_markup=cancel_keyboard(),
    )


@router.message(CreateKeyStates.waiting_custom_days)
async def create_key_custom_days(message: Message, state: FSMContext, services: Services) -> None:
    """Validate the custom expiry days input and show the confirmation."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        text = (message.text or "").strip()
        if not text.isdigit():
            await message.answer(t("days_enter_integer"))
            return
        days = int(text)
        max_days = services.settings.key_max_trial_days
        if days < 1 or days > max_days:
            await message.answer(t("days_enter_range", max=max_days))
            return
        from datetime import datetime, timedelta, timezone
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()
        await state.update_data(expires_at=expires_at)
        await state.set_state(CreateKeyStates.confirming)
        data = await state.get_data()
        key_type = str(data.get("key_type") or "")
        note = data.get("note")
        mtu = int(data["mtu"]) if data.get("mtu") is not None else None
        from bot.keyboards.common import confirm_cancel_keyboard
        await message.answer(
            create_confirm_text(key_type, note, expires_at=expires_at, mtu=mtu),
            reply_markup=confirm_cancel_keyboard("create:confirm"),
        )
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(CreateKeyStates.confirming, F.data == "create:confirm")
async def create_key_confirm(callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter) -> None:
    """Create the VPN key and send its configuration to the user."""
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    key_type = str(data.get("key_type") or "")
    note = data.get("note")
    expires_at: str | None = data.get("expires_at")
    mtu = int(data["mtu"]) if data.get("mtu") is not None else None
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        profile = profile_from_tg(callback.from_user)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        await state.clear()
        await safe_callback_answer(callback, t("creating_key"))
        if key_type == VpnKeyType.XRAY.value:
            result = await services.xray.create_xray_key(callback.from_user.id, profile, note, expires_at=expires_at)
        elif key_type == VpnKeyType.AWG.value:
            result = await services.awg.create_awg_key(callback.from_user.id, profile, note, expires_at=expires_at, mtu=mtu)
        else:
            await safe_edit_message_text(callback.message, t("key_unknown_type"))
            return
        owner_ctx = _admin_owner_context(result.key, callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            result.config_text,
            reply_markup=key_actions_keyboard(result.key, owner_user_id=owner_ctx),
        )
        if result.key.key_type == VpnKeyType.AWG:
            plain = await services.awg.get_awg_client_config_plain(callback.from_user.id, result.key.id, audit=False)
            filename = awg_config_filename(result.key)
            await callback.message.answer_document(BufferedInputFile(plain.encode("utf-8"), filename=filename))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:open:"))
async def open_key(callback: CallbackQuery, services: Services) -> None:
    """Show the detail view for the selected key."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:open")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            key_detail_text(key, viewer_user_id=callback.from_user.id),
            reply_markup=key_actions_keyboard(
                key,
                owner_user_id=owner_context or _admin_owner_context(key, callback.from_user.id),
                page=page_context,
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:show:"))
async def show_key_config(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    """Show the connection configuration for the selected key."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = parse_int_callback(callback.data.rsplit(":", 1)[-1])
        if key_id is None:
            await safe_callback_answer(callback, t("invalid_callback_btn"), show_alert=True)
            return
        rate_limiter.check(callback.from_user.id, "key_show", 5)
        await safe_callback_answer(callback)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if key.key_type == VpnKeyType.XRAY:
            text = xray_config_text(await services.xray.get_xray_key_config(callback.from_user.id, key_id))
            await safe_edit_message_text(
                callback.message,
                text,
                reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
            )
        else:
            text = awg_config_text(await services.awg.get_awg_client_config(callback.from_user.id, key_id))
            plain = await services.awg.get_awg_client_config_plain(callback.from_user.id, key_id)
            await safe_edit_message_text(
                callback.message,
                text,
                reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
            )
            await callback.message.answer_document(
                BufferedInputFile(plain.encode("utf-8"), filename=awg_config_filename(key))
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:stats:"))
async def show_key_stats(callback: CallbackQuery, services: Services) -> None:
    """Refresh and show traffic statistics for the selected key."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = parse_int_callback(callback.data.rsplit(":", 1)[-1])
        if key_id is None:
            await safe_callback_answer(callback, t("invalid_callback_btn"), show_alert=True)
            return
        await safe_callback_answer(callback, t("updating_stats"))
        view = await services.traffic_stats.refresh_for_actor(callback.from_user.id, key_id)
        owner = view.owner
        await services.audit.write(
            actor_user_id=callback.from_user.id,
            action="stats_viewed",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={
                "target_user_id": view.key.owner_user_id,
                "target_username": owner.username if owner else view.key.username,
                "key_type": view.key.key_type.value,
                "label": view.key.email_label,
            },
        )
        await safe_edit_message_text(
            callback.message,
            traffic_stats_text(view, viewer_user_id=callback.from_user.id),
            reply_markup=key_actions_keyboard(view.key, owner_user_id=_admin_owner_context(view.key, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:revoke:"))
async def revoke_key_prompt(callback: CallbackQuery, services: Services) -> None:
    """Prompt the user to confirm revoking the selected key."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:revoke")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        owner_context = owner_context or _admin_owner_context(key, callback.from_user.id)
        if owner_context is not None and owner_context != key.owner_user_id:
            raise AccessDenied(t("revoke_context_stale"))
        await safe_edit_message_text(
            callback.message,
            t("revoke_prompt", key_id=key_id),
            reply_markup=confirm_keyboard("revoke", key_id, owner_user_id=owner_context, page=page_context),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:delete:"))
async def delete_key_prompt(callback: CallbackQuery, services: Services) -> None:
    """Prompt the user to confirm deleting the selected key."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:delete")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        owner_context = owner_context or _admin_owner_context(key, callback.from_user.id)
        if owner_context is not None and owner_context != key.owner_user_id:
            raise AccessDenied(t("delete_context_stale"))
        await safe_edit_message_text(
            callback.message,
            t("delete_prompt", key_id=key_id),
            reply_markup=confirm_keyboard("delete", key_id, owner_user_id=owner_context, page=page_context),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("confirm:"))
async def confirm_key_action(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    """Execute the confirmed revoke or delete action on a key."""
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    if not await ensure_private_callback(callback):
        return
    try:
        action, key_id, owner_context_from_callback, page_context = _parse_confirm_context(callback.data)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if action == "revoke":
            rate_limiter.check(callback.from_user.id, "key_revoke", 10)
            await safe_callback_answer(callback, t("executing"))
            updated = (
                await services.xray.revoke_xray_key(callback.from_user.id, key_id)
                if key.key_type == VpnKeyType.XRAY
                else await services.awg.revoke_awg_key(callback.from_user.id, key_id)
            )
            await safe_edit_message_text(
                callback.message,
                t("key_revoked"),
                reply_markup=key_actions_keyboard(updated, owner_user_id=_admin_owner_context(updated, callback.from_user.id)),
            )
        elif action == "delete":
            rate_limiter.check(callback.from_user.id, "key_delete", 10)
            await safe_callback_answer(callback, t("executing"))
            owner_context = owner_context_from_callback or _admin_owner_context(key, callback.from_user.id)
            if owner_context is not None and owner_context != key.owner_user_id:
                raise AccessDenied(t("delete_context_stale"))
            if key.key_type == VpnKeyType.XRAY:
                await services.xray.delete_xray_key(callback.from_user.id, key_id)
            else:
                await services.awg.delete_awg_key(callback.from_user.id, key_id)
            if owner_context is not None:
                keys, current_page, total_pages, has_next = await load_keys_page(
                    services,
                    callback.from_user.id,
                    owner_user_id=owner_context,
                    page=page_context,
                    page_size=KEYS_PAGE_SIZE,
                )
                await safe_edit_message_text(
                    callback.message,
                    t("key_deleted_with_list", list=keys_page_text(keys, current_page, viewer_user_id=callback.from_user.id, owner_user_id=owner_context)),
                    reply_markup=keys_list_keyboard(
                        keys,
                        page=current_page,
                        has_next=has_next,
                        owner_user_id=owner_context,
                        total_pages=total_pages,
                        back_data=f"admin:user:{owner_context}",
                    ),
                )
                return
            await safe_edit_message_text(
                callback.message,
                t("key_deleted"),
                reply_markup=after_key_deleted_keyboard(),
            )
        else:
            await safe_callback_answer(callback, t("unknown_action"), show_alert=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:note:"))
async def edit_note_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Prompt the user to enter a new note for the selected key."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = parse_int_callback(callback.data.rsplit(":", 1)[-1])
        if key_id is None:
            await safe_callback_answer(callback, t("invalid_callback_btn"), show_alert=True)
            return
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await state.set_state(EditNoteStates.waiting_note)
        await state.update_data(key_id=key_id, cancel_target=f"key:open:{key_id}", note_prompt_msg_id=callback.message.message_id)
        await safe_edit_message_text(
            callback.message,
            t("edit_note_prompt", type=key.key_type.value.upper(), id=key.id),
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(EditNoteStates.waiting_note)
async def edit_note_waiting(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """Store the new note input and show the note change confirmation."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    data = await state.get_data()
    try:
        key_id = int(data["key_id"])
        note_prompt_msg_id = data.get("note_prompt_msg_id")
        key = await services.vpn_keys.get_for_actor(message.from_user.id, key_id)
        note = _clean_note(message.text)
        await state.update_data(note=note)
        if note_prompt_msg_id:
            with suppress(Exception):
                await bot.delete_message(chat_id=message.chat.id, message_id=note_prompt_msg_id)
        await state.set_state(EditNoteStates.confirming)
        await message.answer(note_confirm_text(key, note), reply_markup=confirm_cancel_keyboard("note:confirm"))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(EditNoteStates.confirming, F.data == "note:confirm")
async def edit_note_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Save the updated note for the key and return to its detail view."""
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback, t("saving"))
    data = await state.get_data()
    await state.clear()
    try:
        key_id = int(data["key_id"])
        note = data.get("note")
        await services.notes.update_key_note(callback.from_user.id, key_id, note)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            t("note_updated"),
            reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "trial:request")
async def trial_request_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Start the trial request flow by prompting for a protocol."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        can = await services.trial_access.can_request_trial(callback.from_user.id)
        if not can:
            await safe_callback_answer(callback, t("trial_already_used"), show_alert=True)
            return
        await safe_callback_answer(callback)
        await state.set_state(TrialRequestStates.choosing_protocol)
        await safe_edit_message_text(
            callback.message,
            t("trial_choose_protocol"),
            reply_markup=trial_protocol_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(TrialRequestStates.choosing_protocol, F.data.regexp(r"^trial:proto:(xray|awg)$"))
async def trial_request_proto(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot, rate_limiter: RateLimiter) -> None:
    """Submit the trial request for the chosen protocol and notify admins."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        rate_limiter.check(callback.from_user.id, "trial_request", 300)
        proto = callback.data.rsplit(":", 1)[-1]
        key_type = VpnKeyType(proto)
        can = await services.trial_access.can_request_trial(callback.from_user.id)
        if not can:
            await state.clear()
            await safe_callback_answer(callback, t("trial_already_used"), show_alert=True)
            return
        req = await services.trial_access.create_trial_request(callback.from_user.id, key_type)
        await state.clear()
        await safe_callback_answer(callback, t("trial_request_sent"))
        type_label = "Xray" if proto == "xray" else "AWG"
        await safe_edit_message_text(
            callback.message,
            t("trial_request_submitted"),
        )
        from bot.keyboards.admin import trial_request_keyboard
        text = t(
            "trial_admin_notify",
            user_id=callback.from_user.id,
            protocol=type_label,
            req_id=req.id,
        )
        for admin_id in services.settings.admin_ids:
            try:
                await bot.send_message(admin_id, text, reply_markup=trial_request_keyboard(req.id))
            except Exception:  # noqa: S110
                pass
    except Exception as exc:
        await state.clear()
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^trial:show:\d+$"))
async def trial_key_show(callback: CallbackQuery, services: Services) -> None:
    """Show the configuration for the user's trial key."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if key.owner_user_id != callback.from_user.id:
            await safe_callback_answer(callback, t("trial_no_access"), show_alert=True)
            return
        await safe_callback_answer(callback)
        if key.key_type == VpnKeyType.XRAY:
            text = xray_config_text(await services.xray.get_xray_key_config_for_owner(callback.from_user.id, key_id))
            await safe_edit_message_text(callback.message, text)
        else:
            text = awg_config_text(await services.awg.get_awg_formatted_config_for_owner(callback.from_user.id, key_id))
            plain = await services.awg.get_awg_client_config_for_owner(callback.from_user.id, key_id)
            await safe_edit_message_text(callback.message, text)
            await callback.message.answer_document(
                BufferedInputFile(plain.encode("utf-8"), filename=awg_config_filename(key))
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _parse_mtu(text: str) -> int | None:
    text = text.strip()
    if not text.isdigit():
        return None
    value = int(text)
    return value if 1 <= value <= 1500 else None


def _clean_note(value: str | None) -> str | None:
    if value is None:
        return None
    note = value.strip()
    return None if note in {"", "-"} else note


def _admin_owner_context(key: Any, actor_user_id: int) -> int | None:
    return key.owner_user_id if key.owner_user_id != actor_user_id else None


async def _ensure_can_enter_create(actor_user_id: int, services: Services) -> None:
    try:
        await services.users.require_approved_or_admin(actor_user_id)
    except NotFound as exc:
        raise AccessDenied(t("ensure_send_start")) from exc
    except AccessDenied as exc:
        if "не одобрен" in str(exc) or "not approved" in str(exc).lower():
            raise AccessDenied(t("access_not_approved")) from exc
        raise


def _parse_key_context(data: str | None, prefix: str) -> tuple[int, int | None, int]:
    if not data:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    parts = data.split(":")
    expected = prefix.split(":")
    if parts[: len(expected)] != expected or len(parts) not in {len(expected) + 1, len(expected) + 3}:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    try:
        key_id = int(parts[len(expected)])
        if len(parts) == len(expected) + 1:
            return key_id, None, 0
        return key_id, int(parts[len(expected) + 1]), max(int(parts[len(expected) + 2]), 0)
    except (ValueError, OverflowError):
        raise InvalidCallbackData(t("invalid_callback_btn")) from None


def _parse_confirm_context(data: str) -> tuple[str, int, int | None, int]:
    parts = data.split(":")
    if len(parts) not in {3, 5} or parts[0] != "confirm":
        raise InvalidCallbackData(t("invalid_callback_btn"))
    action = parts[1]
    try:
        key_id = int(parts[2])
        if len(parts) == 3:
            return action, key_id, None, 0
        return action, key_id, int(parts[3]), max(int(parts[4]), 0)
    except (ValueError, OverflowError):
        raise InvalidCallbackData(t("invalid_callback_btn")) from None


async def load_keys_page(
    services: Services,
    actor_user_id: int,
    *,
    owner_user_id: int | None = None,
    page: int,
    page_size: int,
) -> tuple[Any, int, int, bool]:
    """Load a clamped page of keys and return them with pagination metadata."""
    total_count = await services.vpn_keys.count_for_actor(actor_user_id, owner_user_id=owner_user_id)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    current_page = min(max(page, 0), total_pages - 1)
    keys = await services.vpn_keys.list_for_actor(
        actor_user_id,
        owner_user_id=owner_user_id,
        limit=page_size,
        offset=page_offset(current_page, page_size),
    )
    if not keys and current_page > 0:
        total_count = await services.vpn_keys.count_for_actor(actor_user_id, owner_user_id=owner_user_id)
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        current_page = max(0, min(current_page - 1, total_pages - 1))
        keys = await services.vpn_keys.list_for_actor(
            actor_user_id,
            owner_user_id=owner_user_id,
            limit=page_size,
            offset=page_offset(current_page, page_size),
        )
    has_next = current_page + 1 < total_pages
    return keys, current_page, total_pages, has_next


def _page_from_callback(data: str | None, default: int = 0) -> int:
    if not data:
        return default
    parts = data.split(":")
    if parts and parts[-1].isdigit():
        try:
            return max(min(int(parts[-1]), MAX_PAGE), 0)
        except (ValueError, OverflowError):
            return default
    return default
