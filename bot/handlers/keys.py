
from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import (
    XHTTP_PROFILE_CHOICES,
    awg_config_text,
    create_confirm_text,
    hysteria2_config_text,
    key_screen_text,
    keys_page_text,
    note_confirm_text,
    xhttp_profile_prompt,
    xray_config_text,
)
from bot.bundles import (
    BUNDLE_KEY_TYPE,
    bundle_create_confirm_text,
    bundle_created_text,
    bundle_detail_text,
    bundle_has_vless,
    bundle_note_confirm_text,
    require_subscription_ui,
    subscription_ui_enabled,
)
from bot.container import Services
from bot.fsm.states import CreateKeyStates, EditFpStates, EditNoteStates, TrialRequestStates
from bot.handlers.common import (
    InvalidCallbackData,
    answer_callback_error,
    answer_message_error,
    parse_int_callback,
    profile_from_tg,
    stats_views_for_screen,
)
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.key_bundles import bundle_actions_keyboard, bundle_awg_ack_keyboard
from bot.keyboards.keys import (
    VALID_FINGERPRINTS,
    after_key_deleted_keyboard,
    confirm_keyboard,
    create_key_keyboard,
    expiry_choice_keyboard,
    fp_choice_keyboard,
    key_actions_keyboard,
    keys_list_keyboard,
    mtu_choice_keyboard,
    trial_protocol_keyboard,
    vless_transport_keyboard,
    xhttp_profile_keyboard,
)
from aiogram.types import BufferedInputFile
from bot.messages import (
    awg_config_filename,
    config_document_present,
    discard_config_document,
    remember_config_document,
    safe_callback_answer,
    safe_edit_message_text,
)
from bot.pagination import MAX_PAGE, page_offset
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimiter
from i18n import t
from models.access import is_blocked_user
from models.dto import KeyBundle, TelegramUserProfile, TrafficStats, VpnKey
from models.enums import AuditEntityType, VpnKeyType
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.key_bundles import KeyBundleCreateResult
from services.notes import MAX_NOTE_LENGTH

logger = logging.getLogger(__name__)
router = Router()
# Entries per «My keys» page. Each entry is a multi-line card plus its button, and
# the cards grew a traffic block, so three is what still fits on a phone screen
# without the list turning into a scroll.
KEYS_PAGE_SIZE = 3
# Entries per page in the ADMIN view of one user's keys. A different list with a
# different reader: an admin is auditing an account, not managing their own keys,
# and their cards carry no owner-private note, so more of them fit. It lives here,
# beside ``load_list_page``, because the delete handler below re-renders that very
# list — the page size has to be one value shared by both, or a delete would
# repaginate the admin's list to a different size than the list itself uses.
ADMIN_KEYS_PAGE_SIZE = 5
# How deep ``load_list_page`` reads into each source before merging them. Matches
# the repositories' own ``_clamp_limit`` ceiling, so asking for more would silently
# return less.
MERGE_WINDOW_LIMIT = 500


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
        items, current_page, total_pages, has_next = await load_list_page(
            services,
            callback.from_user.id,
            page=page,
            page_size=KEYS_PAGE_SIZE,
        )
        await safe_edit_message_text(
            callback.message,
            keys_page_text(items, current_page, viewer_user_id=callback.from_user.id),
            reply_markup=keys_list_keyboard(
                items, page=current_page, has_next=has_next, total_pages=total_pages
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.in_({"keys:create", "keys:create:menu"}))
async def create_key_menu(callback: CallbackQuery, services: Services) -> None:
    """Show the key type selection menu for creating a key.

    Entered either from the main menu (``keys:create:menu`` → back returns to the
    main menu) or from the «My keys» list (``keys:create`` → back returns to the
    list), so the «back» button honours where the user came from.
    """
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
        xray_on = await services.modules.is_enabled("xray")
        awg_on = await services.modules.is_enabled("awg")
        hy2_on = (
            services.settings.hysteria2_enabled
            and services.settings.is_hysteria2_ready()
            and await services.modules.is_enabled("hysteria2")
        )
        back_data = "menu:main" if callback.data == "keys:create:menu" else "keys:list"
        await safe_edit_message_text(
            callback.message,
            f"{t('one_key_one_device')}\n\n{t('choose_key_type')}",
            reply_markup=create_key_keyboard(
                xray_enabled=xray_on,
                awg_enabled=awg_on,
                xhttp_enabled=services.settings.xray_xhttp_enabled,
                hysteria2_enabled=hy2_on,
                bundle_enabled=subscription_ui_enabled(services),
                back_data=back_data,
            ),
        )


@router.callback_query(F.data == "keys:create:bundle")
async def create_key_choose_bundle(callback: CallbackQuery, services: Services) -> None:
    """Show the AmneziaWG notice before the all-in-one wizard starts.

    The set cannot carry AmneziaWG, and a user who picked «All-in-One» precisely to
    stop juggling keys will otherwise discover that at the end. The same notice the
    subscription's own screens carry is therefore shown up front, and continuing is
    the acknowledgement — see :func:`create_key_bundle_ack`.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        require_subscription_ui(services)
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            t("bundle_awg_separate"),
            reply_markup=bundle_awg_ack_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "keys:create:bundle:ack")
async def create_key_bundle_ack(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Enter the shared create wizard for an all-in-one subscription bundle.

    No separate flow: the bundle rides the very same note → expiry → confirm steps
    a single key uses (it skips MTU, a per-protocol client setting the children get
    from their own defaults, and asks for the fingerprint once for all of them).
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        require_subscription_ui(services)
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
        await state.set_state(CreateKeyStates.waiting_note)
        await state.update_data(
            key_type=BUNDLE_KEY_TYPE,
            transport="tcp",
            cancel_target="keys:create",
            note_prompt_msg_id=callback.message.message_id,
        )
        await safe_edit_message_text(
            callback.message,
            f"{t('note_create_warning')}\n\n{t('key_note_prompt')}",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "keys:proto:vless")
async def create_key_proto_vless(callback: CallbackQuery, services: Services) -> None:
    """Show the VLESS transport selection (step 2) for the chosen VLESS protocol."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            t("choose_vless_transport"),
            reply_markup=vless_transport_keyboard(xhttp_enabled=services.settings.xray_xhttp_enabled),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# Maps the protocol/transport callback to (key_type, transport). VLESS (HTTP)
# is NOT here: it first goes through the XHTTP transport-profile step below.
_CREATE_CHOICE: dict[str, tuple[str, str]] = {
    "keys:create:awg": (VpnKeyType.AWG.value, "tcp"),
    "keys:create:xray": (VpnKeyType.XRAY.value, "tcp"),
    # Hysteria2 has no transport variants; the value is unused for hy2 keys.
    "keys:create:hy2": (VpnKeyType.HYSTERIA2.value, "tcp"),
}


@router.callback_query(F.data.in_(set(_CREATE_CHOICE)))
async def create_key_choose(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Record the chosen key type/transport and prompt for a note."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        key_type, transport = _CREATE_CHOICE[callback.data]
        if not await _protocol_enabled(services, key_type):
            await safe_callback_answer(callback, t("protocol_unavailable"), show_alert=True)
            return
        await safe_callback_answer(callback)
        await state.set_state(CreateKeyStates.waiting_note)
        await state.update_data(
            key_type=key_type,
            transport=transport,
            cancel_target="keys:create",
            note_prompt_msg_id=callback.message.message_id,
        )
        await safe_edit_message_text(
            callback.message,
            f"{t('note_create_warning')}\n\n{t('key_note_prompt')}",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "keys:create:xhttp")
async def create_key_choose_xhttp(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Show the XHTTP transport-profile selection (step 3, VLESS HTTP only)."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        if not services.settings.xray_xhttp_enabled:
            await safe_callback_answer(callback, t("vless_http_unavailable"), show_alert=True)
            return
        await safe_callback_answer(callback)
        await state.set_state(CreateKeyStates.waiting_xhttp_profile)
        await safe_edit_message_text(
            callback.message,
            xhttp_profile_prompt(),
            reply_markup=xhttp_profile_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(CreateKeyStates.waiting_xhttp_profile, F.data.startswith("keys:xhttp:profile:"))
async def create_key_choose_xhttp_profile(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Record the chosen XHTTP profile and prompt for a note."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        if not services.settings.xray_xhttp_enabled:
            await safe_callback_answer(callback, t("vless_http_unavailable"), show_alert=True)
            return
        profile = callback.data.rsplit(":", 1)[-1]
        if profile not in XHTTP_PROFILE_CHOICES:
            await safe_callback_answer(callback, t("xhttp_profile_invalid"), show_alert=True)
            return
        await safe_callback_answer(callback)
        await state.set_state(CreateKeyStates.waiting_note)
        await state.update_data(
            key_type=VpnKeyType.XRAY.value,
            transport="http",
            xhttp_profile=profile,
            cancel_target="keys:create",
            note_prompt_msg_id=callback.message.message_id,
        )
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
        note_error = _note_input_error(note)
        if note_error is not None:
            await message.answer(note_error)
            return
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
        elif key_type == VpnKeyType.XRAY.value:
            await state.set_state(CreateKeyStates.waiting_fp)
            await message.answer(t("fp_prompt"), reply_markup=fp_choice_keyboard())
        elif key_type == BUNDLE_KEY_TYPE and await services.modules.is_enabled("xray"):
            # One choice for all of the bundle's VLESS children at once — asking
            # four times for what is a single client-side setting would be worse
            # than the old behaviour of silently using the global default. Skipped
            # when Xray is off, because then the bundle has no VLESS child to apply
            # it to. Hysteria2 has no fingerprint and ignores the value.
            await state.set_state(CreateKeyStates.waiting_fp)
            await message.answer(t("bundle_fp_prompt"), reply_markup=fp_choice_keyboard())
        else:
            await state.set_state(CreateKeyStates.waiting_expiry)
            await message.answer(t("expiry_prompt"), reply_markup=expiry_choice_keyboard())
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(CreateKeyStates.waiting_fp, F.data.regexp(r"^fp:[\w]+$"))
async def create_key_fp(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Store the chosen fingerprint and advance to expiry selection."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        fp = callback.data.split(":", 1)[1]
        if fp not in VALID_FINGERPRINTS:
            await safe_callback_answer(callback, t("fp_invalid"), show_alert=True)
            return
        await state.update_data(fingerprint=fp)
        await state.set_state(CreateKeyStates.waiting_expiry)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            t("expiry_prompt"),
            reply_markup=expiry_choice_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


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
        from bot.keyboards.common import confirm_cancel_keyboard
        await safe_edit_message_text(
            callback.message,
            _create_confirm_screen(data, expires_at),
            reply_markup=confirm_cancel_keyboard("create:confirm"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(CreateKeyStates.waiting_expiry, F.data == "expiry:custom")
async def create_key_expiry_custom(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Prompt the user to enter a custom number of expiry days."""
    if not await ensure_private_callback(callback):
        return
    if callback.message is None:
        return
    await safe_callback_answer(callback)
    await state.set_state(CreateKeyStates.waiting_custom_days)
    await safe_edit_message_text(
        callback.message,
        t("expiry_custom_prompt", max=services.settings.key_max_trial_days),
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
            await message.answer(t("days_enter_integer", max=services.settings.key_max_trial_days))
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
        from bot.keyboards.common import confirm_cancel_keyboard
        await message.answer(
            _create_confirm_screen(data, expires_at),
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
    transport = str(data.get("transport") or "tcp")
    note = data.get("note")
    expires_at: str | None = data.get("expires_at")
    mtu = int(data["mtu"]) if data.get("mtu") is not None else None
    fingerprint: str | None = data.get("fingerprint")
    xhttp_profile = str(data.get("xhttp_profile") or "base")
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        profile = profile_from_tg(callback.from_user)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        if key_type == BUNDLE_KEY_TYPE:
            require_subscription_ui(services)
            await state.clear()
            await safe_callback_answer(callback, t("creating_bundle"))
            bundle_result = await _create_bundle(
                services, callback.from_user.id, profile, note, expires_at, fingerprint
            )
            await safe_edit_message_text(
                callback.message,
                bundle_created_text(
                    bundle_result,
                    viewer_user_id=callback.from_user.id,
                    settings=services.settings,
                ),
                reply_markup=bundle_actions_keyboard(
                    bundle_result.bundle, has_vless=bundle_has_vless(list(bundle_result.keys))
                ),
            )
            return
        await state.clear()
        await safe_callback_answer(callback, t("creating_key"))
        if key_type == VpnKeyType.XRAY.value:
            result = await services.xray.create_xray_key(callback.from_user.id, profile, note, expires_at=expires_at, fingerprint=fingerprint, transport=transport, xhttp_profile=xhttp_profile)
        elif key_type == VpnKeyType.AWG.value:
            result = await services.awg.create_awg_key(callback.from_user.id, profile, note, expires_at=expires_at, mtu=mtu)
        elif key_type == VpnKeyType.HYSTERIA2.value:
            result = await services.hysteria.issue(callback.from_user.id, profile, note, expires_at=expires_at)
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
            sent = await callback.message.answer_document(BufferedInputFile(plain.encode("utf-8"), filename=filename))
            await remember_config_document(state, key_id=result.key.id, message_id=sent.message_id)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:open:"))
async def open_key(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    """Show the detail view for the selected key, its traffic included.

    The traffic used to live behind a «Статистика» button; it is part of the card
    now, so this screen samples it (softly rate-limited, cached fallback) instead
    of making the user ask for it.
    """
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:open")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        owner_context = owner_context or _admin_owner_context(key, callback.from_user.id)
        if owner_context is not None and owner_context != key.owner_user_id:
            raise AccessDenied(t("invalid_callback_btn"))
        # Before the render, never after: the figures must not reach the screen
        # unless the record of who read them was written first.
        await _audit_foreign_stats_view(services, callback.from_user.id, key)
        await safe_edit_message_text(
            callback.message,
            key_screen_text(
                key,
                viewer_user_id=callback.from_user.id,
                stats=await _key_stats(services, rate_limiter, callback.from_user.id, key),
            ),
            reply_markup=key_actions_keyboard(
                key,
                owner_user_id=owner_context,
                page=page_context,
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _key_stats(
    services: Services, rate_limiter: RateLimiter, actor_user_id: int, key: VpnKey
) -> TrafficStats | None:
    """Traffic for one key's screen, or None when nothing could be read."""
    views = await stats_views_for_screen(services, rate_limiter, actor_user_id, [key])
    return views[0].stats if views else None


async def _audit_foreign_stats_view(services: Services, actor_user_id: int, key: VpnKey) -> None:
    """Record an admin reading someone else's traffic — and only that.

    The traffic figures moved onto the key screen, so auditing every render would
    write a row per navigation tap and bury the log. What the trail is actually for
    is accountability across users: an owner looking at their own counters is not
    an event, an admin looking at another user's is.
    """
    if key.owner_user_id == actor_user_id:
        return
    await services.audit.write(
        actor_user_id=actor_user_id,
        action="stats_viewed",
        entity_type=AuditEntityType.VPN_KEY,
        entity_id=key.id,
        details={
            "target_user_id": key.owner_user_id,
            "target_username": key.username,
            "key_type": key.key_type.value,
            "label": key.email_label,
        },
    )


@router.callback_query(F.data.startswith("key:show:"))
async def show_key_config(callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter, bot: Bot) -> None:
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
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        keyboard = key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id))
        if key.key_type == VpnKeyType.XRAY:
            await safe_callback_answer(callback)
            text = xray_config_text(await services.xray.get_xray_key_config(callback.from_user.id, key_id))
            await safe_edit_message_text(callback.message, text, reply_markup=keyboard)
            return
        if key.key_type == VpnKeyType.HYSTERIA2:
            await safe_callback_answer(callback)
            text = hysteria2_config_text(await services.hysteria.get_config(callback.from_user.id, key_id))
            await safe_edit_message_text(callback.message, text, reply_markup=keyboard)
            return
        text = awg_config_text(await services.awg.get_awg_client_config(callback.from_user.id, key_id))
        await safe_edit_message_text(callback.message, text, reply_markup=keyboard)
        # The config file is still on screen — don't send a duplicate.
        if await config_document_present(state, key_id):
            await safe_callback_answer(callback, t("config_already_sent"))
            return
        # A leftover file for a different key may linger; drop it before sending.
        await discard_config_document(state, bot, callback.message.chat.id)
        plain = await services.awg.get_awg_client_config_plain(callback.from_user.id, key_id)
        await safe_callback_answer(callback)
        sent = await callback.message.answer_document(
            BufferedInputFile(plain.encode("utf-8"), filename=awg_config_filename(key))
        )
        await remember_config_document(state, key_id=key_id, message_id=sent.message_id)
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
            if key.key_type == VpnKeyType.XRAY:
                updated = await services.xray.revoke_xray_key(callback.from_user.id, key_id)
            elif key.key_type == VpnKeyType.HYSTERIA2:
                updated = await services.hysteria.revoke(callback.from_user.id, key_id)
            else:
                updated = await services.awg.revoke_awg_key(callback.from_user.id, key_id)
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
            elif key.key_type == VpnKeyType.HYSTERIA2:
                await services.hysteria.delete_hysteria2_key(callback.from_user.id, key_id)
            else:
                await services.awg.delete_awg_key(callback.from_user.id, key_id)
            if owner_context is not None:
                items, current_page, total_pages, has_next = await load_list_page(
                    services,
                    callback.from_user.id,
                    owner_user_id=owner_context,
                    page=page_context,
                    page_size=ADMIN_KEYS_PAGE_SIZE,
                )
                await safe_edit_message_text(
                    callback.message,
                    t("key_deleted_with_list", list=keys_page_text(items, current_page, viewer_user_id=callback.from_user.id, owner_user_id=owner_context)),
                    reply_markup=keys_list_keyboard(
                        items,
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
        await state.update_data(key_id=key_id, bundle_id=None, cancel_target=f"key:open:{key_id}", note_prompt_msg_id=callback.message.message_id)
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
        note_prompt_msg_id = data.get("note_prompt_msg_id")
        # The same wizard serves keys and all-in-one bundles; ``bundle_id`` in the
        # FSM data is what says which entity the note belongs to.
        bundle_id = data.get("bundle_id")
        if bundle_id is not None:
            require_subscription_ui(services)
            bundle = await services.key_bundle_views.get_for_actor(message.from_user.id, int(bundle_id))
        else:
            key = await services.vpn_keys.get_for_actor(message.from_user.id, int(data["key_id"]))
        note = _clean_note(message.text)
        note_error = _note_input_error(note)
        if note_error is not None:
            await message.answer(note_error)
            return
        await state.update_data(note=note)
        if note_prompt_msg_id:
            with suppress(Exception):
                await bot.delete_message(chat_id=message.chat.id, message_id=note_prompt_msg_id)
        await state.set_state(EditNoteStates.confirming)
        confirm_text = (
            bundle_note_confirm_text(bundle, note) if bundle_id is not None else note_confirm_text(key, note)
        )
        await message.answer(confirm_text, reply_markup=confirm_cancel_keyboard("note:confirm"))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(EditNoteStates.confirming, F.data == "note:confirm")
async def edit_note_confirm(callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter) -> None:
    """Save the updated note for the key and return to its detail view."""
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    try:
        # Checked before clearing state so a throttled tap keeps the pending note.
        rate_limiter.check(callback.from_user.id, "note_edit", 5)
        await safe_callback_answer(callback, t("saving"))
        data = await state.get_data()
        await state.clear()
        note = data.get("note")
        bundle_id = data.get("bundle_id")
        if bundle_id is not None:
            require_subscription_ui(services)
            await services.key_bundle_views.update_note(callback.from_user.id, int(bundle_id), note)
            bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, int(bundle_id))
            keys = await services.key_bundle_views.list_keys_for_actor(callback.from_user.id, bundle.id)
            await safe_edit_message_text(
                callback.message,
                t("note_updated"),
                reply_markup=bundle_actions_keyboard(bundle, has_vless=bundle_has_vless(keys)),
            )
            return
        key_id = int(data["key_id"])
        await services.notes.update_key_note(callback.from_user.id, key_id, note)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            t("note_updated"),
            reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^key:fp:\d+$"))
async def edit_fp_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Show the fingerprint selection keyboard for changing an existing Xray key's fingerprint."""
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
        await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await state.set_state(EditFpStates.waiting_fp)
        # bundle_id is cleared explicitly: the same states serve both entities and
        # update_data merges, so a leftover id would re-target a whole subscription.
        await state.update_data(key_id=key_id, bundle_id=None, cancel_target=f"key:open:{key_id}")
        await safe_edit_message_text(
            callback.message,
            t("fp_change_prompt"),
            reply_markup=fp_choice_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(EditFpStates.waiting_fp, F.data.regexp(r"^fp:[\w]+$"))
async def edit_fp_select(
    callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter
) -> None:
    """Apply the selected fingerprint to the existing Xray key — or to a whole bundle.

    One wizard for both, told apart by ``bundle_id`` in the FSM data exactly like
    the note wizard: a subscription's VLESS children are re-stamped through the
    same per-key service call this handler already made, so neither entity gets a
    fingerprint path of its own to drift.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    fp = callback.data.split(":", 1)[1]
    data = await state.get_data()
    await state.clear()
    try:
        bundle_id = data.get("bundle_id")
        if bundle_id is not None:
            require_subscription_ui(services)
            await safe_callback_answer(callback, t("saving"))
            bundle, changed = await services.key_bundles.change_fingerprint(
                callback.from_user.id, int(bundle_id), fp
            )
            keys = await services.key_bundle_views.list_keys_for_actor(
                callback.from_user.id, bundle.id
            )
            views = await stats_views_for_screen(services, rate_limiter, callback.from_user.id, keys)
            await safe_edit_message_text(
                callback.message,
                f"{t('bundle_fp_updated', count=changed)}\n\n"
                + bundle_detail_text(
                    bundle, keys, viewer_user_id=callback.from_user.id, views=views
                ),
                reply_markup=bundle_actions_keyboard(bundle, has_vless=bundle_has_vless(keys)),
            )
            return
        key_id = int(data["key_id"])
        await safe_callback_answer(callback, t("saving"))
        await services.xray.change_fingerprint(callback.from_user.id, key_id, fp)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            key_screen_text(
                key,
                viewer_user_id=callback.from_user.id,
                stats=await _key_stats(services, rate_limiter, callback.from_user.id, key),
            ),
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
        user = await services.users.get_user(callback.from_user.id)
        if is_blocked_user(user):
            await safe_callback_answer(callback, t("blocked_callback"), show_alert=True)
            return
        can = await services.trial_access.can_request_trial(callback.from_user.id)
        if not can:
            await safe_callback_answer(callback, t("trial_already_used"), show_alert=True)
            return
        await safe_callback_answer(callback)
        await state.set_state(TrialRequestStates.choosing_protocol)
        xray_on = await services.modules.is_enabled("xray")
        awg_on = await services.modules.is_enabled("awg")
        hy2_on = (
            services.settings.hysteria2_enabled
            and services.settings.is_hysteria2_ready()
            and await services.modules.is_enabled("hysteria2")
        )
        await safe_edit_message_text(
            callback.message,
            t("trial_choose_protocol"),
            reply_markup=trial_protocol_keyboard(xray_enabled=xray_on, awg_enabled=awg_on, hysteria2_enabled=hy2_on),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# Maps the trial protocol callback token to (VpnKeyType, display label). The
# token differs from the enum value for Hysteria2 ("hy2" vs "hysteria2"), so the
# mapping is explicit rather than VpnKeyType(token).
_TRIAL_PROTO_CHOICE: dict[str, tuple[VpnKeyType, str]] = {
    "xray": (VpnKeyType.XRAY, "Xray"),
    "awg": (VpnKeyType.AWG, "AWG"),
    "hy2": (VpnKeyType.HYSTERIA2, "Hysteria2"),
}


@router.callback_query(TrialRequestStates.choosing_protocol, F.data.regexp(r"^trial:proto:(xray|awg|hy2)$"))
async def trial_request_proto(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot, rate_limiter: RateLimiter) -> None:
    """Submit the trial request for the chosen protocol and notify admins."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        user = await services.users.get_user(callback.from_user.id)
        if is_blocked_user(user):
            await state.clear()
            await safe_callback_answer(callback, t("blocked_callback"), show_alert=True)
            return
        rate_limiter.check(callback.from_user.id, "trial_request", 300)
        proto = callback.data.rsplit(":", 1)[-1]
        key_type, type_label = _TRIAL_PROTO_CHOICE[proto]
        if not await _protocol_enabled(services, key_type.value):
            await state.clear()
            await safe_callback_answer(callback, t("protocol_unavailable"), show_alert=True)
            return
        can = await services.trial_access.can_request_trial(callback.from_user.id)
        if not can:
            await state.clear()
            await safe_callback_answer(callback, t("trial_already_used"), show_alert=True)
            return
        req = await services.trial_access.create_trial_request(callback.from_user.id, key_type)
        await state.clear()
        await safe_callback_answer(callback, t("trial_request_sent"))
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
async def trial_key_show(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
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
            sent = await callback.message.answer_document(
                BufferedInputFile(plain.encode("utf-8"), filename=awg_config_filename(key))
            )
            # Track the sent AWG config file so the config-cleanup middleware
            # removes it when the user navigates away, like the main key flow.
            await remember_config_document(state, key_id=key_id, message_id=sent.message_id)
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _create_confirm_screen(data: dict[str, Any], expires_at: str | None) -> str:
    """Build the create-wizard confirmation for whichever entity is being created."""
    key_type = str(data.get("key_type") or "")
    note = data.get("note")
    if key_type == BUNDLE_KEY_TYPE:
        return bundle_create_confirm_text(note, expires_at=expires_at, fingerprint=data.get("fingerprint"))
    return create_confirm_text(
        key_type,
        note,
        expires_at=expires_at,
        mtu=int(data["mtu"]) if data.get("mtu") is not None else None,
        fingerprint=data.get("fingerprint"),
        transport=str(data.get("transport") or "tcp"),
        profile=str(data.get("xhttp_profile") or "base"),
    )


async def _create_bundle(
    services: Services,
    actor_user_id: int,
    owner: TelegramUserProfile,
    note: str | None,
    expires_at: str | None,
    fingerprint: str | None = None,
) -> KeyBundleCreateResult:
    """Create an all-in-one bundle, turning a backend fault into a retry message.

    ``KeyBundleService`` raises a *keyed* ``InvalidOperation`` for the states the
    user can act on (feature off, no protocol enabled, creating for someone else)
    and an *unkeyed* one for the transient ones — an enabled-but-degraded backend
    aborts the creation, and a child that failed mid-way is rolled back. Those
    unkeyed messages are operator-facing text about backends and reload modes, so
    they become a plain localized "try again later" instead. Either way the user
    sees an alert and never a traceback: ``InvalidOperation`` is a safe exception
    for ``answer_callback_error``.
    """
    try:
        return await services.key_bundles.create_bundle(
            actor_user_id, owner, note, expires_at=expires_at, fingerprint=fingerprint
        )
    except InvalidOperation as exc:
        if getattr(exc, "key", None):
            raise
        logger.warning(
            "All-in-one subscription creation failed for user_id=%s", actor_user_id, exc_info=True
        )
        raise InvalidOperation(t("bundle_create_failed"), key="bundle_create_failed") from exc


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


def _note_input_error(note: str | None) -> str | None:
    """Return a localized error if the cleaned note is invalid, else None.

    Validating here (at input time) gives the user a fixable message and keeps
    them in the same wizard step, instead of walking the whole flow and hitting
    ``normalize_note``'s ValueError at confirm time (surfaced as a generic
    "internal error"). ``normalize_note`` stays as the service-layer backstop.
    """
    if note is None:
        return None
    if "\n" in note or "\r" in note:
        return t("note_no_newlines")
    if len(note) > MAX_NOTE_LENGTH:
        return t("note_too_long", max=MAX_NOTE_LENGTH)
    return None


def _admin_owner_context(key: Any, actor_user_id: int) -> int | None:
    return key.owner_user_id if key.owner_user_id != actor_user_id else None


async def _ensure_can_enter_create(actor_user_id: int, services: Services) -> None:
    try:
        await services.users.require_approved_or_admin(actor_user_id)
    except NotFound as exc:
        # The user has no account yet: point them at /start. Other AccessDenied
        # cases (blocked / not approved) already carry their own localized key
        # from require_approved_or_admin, so they propagate unchanged.
        raise AccessDenied(t("ensure_send_start"), key="ensure_send_start") from exc


async def _protocol_enabled(services: Services, key_type: str) -> bool:
    """Whether the given protocol is currently offered for key creation.

    Mirrors the availability checks that gate the create-menu buttons, so a
    replayed/stale ``keys:create:*`` (or ``trial:proto:*``) callback for a
    disabled protocol is refused up front instead of walking the whole wizard
    only to fail at the service layer.
    """
    if key_type == VpnKeyType.XRAY.value:
        return await services.modules.is_enabled("xray")
    if key_type == VpnKeyType.AWG.value:
        return await services.modules.is_enabled("awg")
    if key_type == VpnKeyType.HYSTERIA2.value:
        return (
            services.settings.hysteria2_enabled
            and services.settings.is_hysteria2_ready()
            and await services.modules.is_enabled("hysteria2")
        )
    return False


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


def _list_item_sort_key(item: VpnKey | KeyBundle) -> tuple[str, int, int]:
    """Sort key for the merged «My keys» list, applied with ``reverse=True``.

    Newest first, then keys ahead of subscriptions on an identical timestamp, then
    by id. The last two components are not cosmetic: the order has to be *total*,
    or two entries created in the same second could swap places between two fetches
    and a page boundary would then show one of them twice and the other never.
    """
    return (item.created_at, 0 if isinstance(item, KeyBundle) else 1, item.id)


async def load_list_page(
    services: Services,
    actor_user_id: int,
    *,
    owner_user_id: int | None = None,
    page: int,
    page_size: int,
) -> tuple[list[VpnKey | KeyBundle], int, int, bool]:
    """Load a clamped page of «My keys» — keys and all-in-one subscriptions in one
    date-sorted list — with its pagination metadata.

    The page size counts *entries*, so a page really holds ``page_size`` cards.
    Subscriptions used to be appended to page 0 as an extra group on top of a full
    page of keys, which is how a "5 per page" list ended up showing ten.

    Two paths, because merging is only needed when there is something to merge:

    * no subscriptions in play (the admin view of another user's keys, the feature
      switched off, or simply a user without any) — the plain LIMIT/OFFSET query,
      exactly as before and at the same cost;
    * otherwise both sides are fetched from the top and merged in Python. A
      window of ``(page + 1) * page_size`` rows per side is enough, since the page
      being rendered cannot contain an entry that is deeper than that in either
      source. The window is capped at the repositories' own ``_clamp_limit``
      ceiling, so a user holding both subscriptions and more than 500 entries would
      see the tail of the list mis-ordered; nothing in this bot's shape gets near
      that, and the alternative (a UNION query spanning two repositories) is not
      worth it until something does.

    Bundle children stay hidden in the user's own view — they are revoked and
    deleted through their parent, and listing all five under it buried the card —
    while the admin view still shows every key, since it has no bundle screen to
    see them on instead.
    """
    include_bundles = owner_user_id is None and subscription_ui_enabled(services)
    exclude_bundled = owner_user_id is None

    async def load_totals() -> tuple[int, int]:
        keys_total = await services.vpn_keys.count_for_actor(
            actor_user_id, owner_user_id=owner_user_id, exclude_bundled=exclude_bundled
        )
        bundles_total = (
            await services.key_bundle_views.count_for_actor(actor_user_id) if include_bundles else 0
        )
        return keys_total, bundles_total

    async def load_page(current_page: int, bundles_total: int) -> list[VpnKey | KeyBundle]:
        if bundles_total == 0:
            keys = await services.vpn_keys.list_for_actor(
                actor_user_id,
                owner_user_id=owner_user_id,
                limit=page_size,
                offset=page_offset(current_page, page_size),
                exclude_bundled=exclude_bundled,
            )
            return list(keys)
        window = min((current_page + 1) * page_size, MERGE_WINDOW_LIMIT)
        keys = await services.vpn_keys.list_for_actor(
            actor_user_id,
            owner_user_id=owner_user_id,
            limit=window,
            offset=0,
            exclude_bundled=exclude_bundled,
        )
        bundles = await services.key_bundle_views.list_for_actor(actor_user_id, limit=window)
        merged: list[VpnKey | KeyBundle] = [*keys, *bundles]
        merged.sort(key=_list_item_sort_key, reverse=True)
        start = page_offset(current_page, page_size)
        return merged[start : start + page_size]

    keys_total, bundles_total = await load_totals()
    total_pages = max(1, (keys_total + bundles_total + page_size - 1) // page_size)
    current_page = min(max(page, 0), total_pages - 1)
    items = await load_page(current_page, bundles_total)
    if not items and current_page > 0:
        # Entries disappeared between the count and the fetch — step back a page
        # rather than showing an empty list with a «next» button.
        keys_total, bundles_total = await load_totals()
        total_pages = max(1, (keys_total + bundles_total + page_size - 1) // page_size)
        current_page = max(0, min(current_page - 1, total_pages - 1))
        items = await load_page(current_page, bundles_total)
    has_next = current_page + 1 < total_pages
    return items, current_page, total_pages, has_next


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
