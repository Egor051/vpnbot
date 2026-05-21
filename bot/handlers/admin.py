
import logging
from dataclasses import replace
from typing import Any

from aiogram import Bot, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.formatters import (
    NOTE_CREATE_WARNING,
    ONE_KEY_ONE_DEVICE_WARNING,
    access_request_text,
    access_request_decision_confirm_text,
    access_requests_page_text,
    announcement_batches_text,
    admin_stats_page_text,
    admin_proxy_stats_text,
    proxy_admin_status_text,
    audit_page_text,
    block_user_confirm_text,
    create_confirm_text,
    keys_page_text,
    system_diagnostics_text,
    unblock_user_confirm_text,
    unblock_user_success_text,
    user_card_text,
    users_page_text,
)
from services.health import run_bot_health
from bot.fsm.states import AdminCreateKeyStates, AdminAnnouncementStates, AdminEditUserNoteStates
from bot.guards import require_superadmin, require_moderator_or_admin
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.admin import (
    admin_issue_users_keyboard,
    admin_key_type_keyboard,
    admin_panel_keyboard,
    moderator_panel_keyboard,
    announcement_batches_keyboard,
    announcement_confirm_keyboard,
    access_request_decision_confirm_keyboard,
    block_user_confirm_keyboard,
    pending_requests_keyboard,
    unblock_user_confirm_keyboard,
    user_actions_keyboard,
    users_keyboard,
)
from bot.handlers.keys import load_keys_page
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.keys import expiry_choice_keyboard, key_actions_keyboard, keys_list_keyboard, mtu_choice_keyboard
from bot.messages import awg_config_filename, safe_callback_answer, safe_edit_message_text, send_awg_config
from bot.pagination import page_offset, split_page
from bot.private_chat import ADMIN_PRIVATE_ONLY_TEXT, ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimitExceeded, RateLimiter
from models.dto import TelegramUserProfile
from models.access import is_blocked_user
from models.enums import AccessRequestStatus, UserRole, VpnKeyType
from services.user_locks import UserLockManager

router = Router()
logger = logging.getLogger(__name__)
_announcement_confirm_locks = UserLockManager()

ADMIN_PAGE_SIZE = 8
ADMIN_KEYS_PAGE_SIZE = 5
AUDIT_PAGE_SIZE = 12
ADMIN_PROXY_USER_LIMIT = 10


@router.message(Command("admin"))
async def admin_command(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        await message.answer("Админ-панель:", reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(F.text == "Админ-панель")
async def admin_menu_message(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        await message.answer("Админ-панель:", reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "admin:panel")
async def admin_panel(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, "Админ-панель:", reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(Command("moderator"))
async def moderator_command(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_moderator_or_admin(services, message.from_user.id)
        await message.answer("Панель модератора:", reply_markup=moderator_panel_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(F.text == "Панель модератора")
async def moderator_menu_message(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_moderator_or_admin(services, message.from_user.id)
        await message.answer("Панель модератора:", reply_markup=moderator_panel_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "admin:moderator_panel")
async def moderator_panel_callback(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_moderator_or_admin(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, "Панель модератора:", reply_markup=moderator_panel_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:announce")
async def admin_announcement_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        await state.set_state(AdminAnnouncementStates.waiting_message)
        await safe_edit_message_text(
            callback.message,
            "Отправьте сообщение объявления. Оно будет разослано одобренным пользователям без изменений после подтверждения.",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminAnnouncementStates.waiting_message)
async def admin_announcement_message(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        recipient_count = await services.announcements.count_recipients(message.from_user.id)
        await state.update_data(from_chat_id=message.chat.id, message_id=message.message_id)
        await state.set_state(AdminAnnouncementStates.confirming)
        await message.answer(
            (
                "Разослать это объявление пользователям?\n"
                f"Получателей среди одобренных пользователей: {recipient_count}\n"
                "Сообщение будет отправлено без дополнительных подписей."
            ),
            reply_markup=announcement_confirm_keyboard(),
        )
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminAnnouncementStates.confirming, F.data == "admin:announce:send")
async def admin_announcement_send(
    callback: CallbackQuery,
    state: FSMContext,
    services: Services,
    bot: Bot,
    rate_limiter: RateLimiter | None = None,
) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        async with _announcement_confirm_locks.lock(callback.from_user.id):
            await require_superadmin(services, callback.from_user.id)
            data = await state.get_data()
            if "from_chat_id" not in data or "message_id" not in data:
                await safe_callback_answer(callback, "Объявление уже отправлено или устарело.", show_alert=True)
                return
            from_chat_id = int(data["from_chat_id"])
            message_id = int(data["message_id"])
            if rate_limiter is not None:
                rate_limiter.check(callback.from_user.id, "announcement_send", 20)
            await state.clear()
            await safe_callback_answer(callback, "Отправляю...")
            result = await services.announcements.send_to_all(
                actor_user_id=callback.from_user.id,
                bot=bot,
                from_chat_id=from_chat_id,
                message_id=message_id,
            )
        await safe_edit_message_text(
            callback.message,
            (
                "Объявление отправлено.\n"
                f"Получателей: {result.total}\n"
                f"Успешно: {result.success}\n"
                f"Ошибок: {result.failed}"
            ),
            reply_markup=admin_panel_keyboard(),
        )
    except RateLimitExceeded as exc:
        await answer_callback_error(callback, exc)
    except Exception as exc:
        await state.clear()
        await answer_callback_error(callback, exc)


@router.callback_query(AdminAnnouncementStates.confirming, F.data == "admin:announce:schedule")
async def admin_announcement_schedule_request(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.set_state(AdminAnnouncementStates.waiting_schedule_time)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            "Введите дату и время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ (московское время):",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminAnnouncementStates.waiting_schedule_time)
async def admin_announcement_schedule_time(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        scheduled_at = _parse_schedule_time(message.text or "")
        if scheduled_at is None:
            await message.answer(
                "Неверный формат или время в прошлом.\n"
                "Введите дату и время в формате ДД.ММ.ГГГГ ЧЧ:ММ (московское время):"
            )
            return
        data = await state.get_data()
        if "from_chat_id" not in data or "message_id" not in data:
            await state.clear()
            await message.answer("Сессия устарела, начните заново.", reply_markup=admin_panel_keyboard())
            return
        from_chat_id = int(data["from_chat_id"])
        message_id = int(data["message_id"])
        await state.clear()
        batch = await services.announcements.schedule_to_all(
            actor_user_id=message.from_user.id,
            from_chat_id=from_chat_id,
            message_id=message_id,
            scheduled_at=scheduled_at,
        )
        from datetime import datetime, timezone, timedelta
        dt = datetime.fromisoformat(scheduled_at).replace(tzinfo=timezone.utc)
        msk_str = (dt + timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")
        await message.answer(
            f"Объявление запланировано.\n"
            f"Batch #{batch.id}\n"
            f"Получателей: {batch.total_count}\n"
            f"Время отправки: {msk_str} МСК",
            reply_markup=admin_panel_keyboard(),
        )
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminAnnouncementStates.confirming, F.data == "admin:announce:cancel")
async def admin_announcement_cancel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await state.clear()
    await safe_callback_answer(callback, "Отменено")
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, "Админ-панель:", reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:announce_batches")
async def admin_announcement_batches(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обновляю список...")
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await _show_announcement_batches(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:announce:(resume|retry|cancelbatch):\d+$"))
async def admin_announcement_batch_action(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        _admin, _announce, action, raw_batch_id = callback.data.split(":", 3)
        batch_id = int(raw_batch_id)
        if action == "cancelbatch":
            await safe_callback_answer(callback, "Отменяю...")
            result = await services.announcements.cancel_batch(
                actor_user_id=callback.from_user.id,
                announcement_id=batch_id,
            )
            prefix = f"Batch #{result.batch.id} отменён." if result.changed else f"Batch #{result.batch.id} уже был отменён."
        else:
            await safe_callback_answer(callback, "Восстанавливаю отправку...")
            resume_result = await services.announcements.resume_batch(
                actor_user_id=callback.from_user.id,
                bot=bot,
                announcement_id=batch_id,
                retry_failed=action == "retry",
            )
            prefix = (
                f"Batch #{resume_result.announcement_id} обработан.\n"
                f"Получателей: {resume_result.total}; успешно: {resume_result.success}; ошибок: {resume_result.failed}."
            )
        await _show_announcement_batches(callback, services, prefix=prefix)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:reqs(?::\d+)?$"))
async def admin_requests(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        await services.users.require_moderator_or_admin(callback.from_user.id)
        items = await services.access.list_pending(
            callback.from_user.id,
            limit=ADMIN_PAGE_SIZE + 1,
            offset=page_offset(page, ADMIN_PAGE_SIZE),
        )
        requests, has_next = split_page(items, ADMIN_PAGE_SIZE)
        await safe_edit_message_text(
            callback.message,
            access_requests_page_text(requests, page),
            reply_markup=pending_requests_keyboard(requests, page=page, has_next=has_next),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:req:"))
async def admin_request_detail(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await services.users.require_moderator_or_admin(callback.from_user.id)
        request_id = int(callback.data.rsplit(":", 1)[-1])
        request = await services.access.get_request(callback.from_user.id, request_id)
        await safe_edit_message_text(callback.message, access_request_text(request), reply_markup=pending_requests_keyboard([request]))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:approve:\d+$"))
async def admin_approve(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        request_id = int(callback.data.rsplit(":", 1)[-1])
        request = await services.access.get_request(callback.from_user.id, request_id)
        if callback.message:
            if request.status != AccessRequestStatus.PENDING:
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=pending_requests_keyboard([], page=0))
                return
            await safe_edit_message_text(
                callback.message,
                access_request_decision_confirm_text(request, "approve"),
                reply_markup=access_request_decision_confirm_keyboard(request.id, "approve"),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:reject:\d+$"))
async def admin_reject(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        request_id = int(callback.data.rsplit(":", 1)[-1])
        request = await services.access.get_request(callback.from_user.id, request_id)
        if callback.message:
            if request.status != AccessRequestStatus.PENDING:
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=pending_requests_keyboard([], page=0))
                return
            await safe_edit_message_text(
                callback.message,
                access_request_decision_confirm_text(request, "reject"),
                reply_markup=access_request_decision_confirm_keyboard(request.id, "reject"),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:(approve|reject):confirm:\d+$"))
async def admin_access_decision_confirm(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обрабатываю...")
    try:
        _admin, action, _confirm, raw_request_id = callback.data.split(":", 3)
        request_id = int(raw_request_id)
        current = await services.access.get_request(callback.from_user.id, request_id)
        if current.status != AccessRequestStatus.PENDING:
            if callback.message:
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=pending_requests_keyboard([], page=0))
            return
        if action == "approve":
            request, changed = await services.access.approve(callback.from_user.id, request_id)
            if changed:
                await _safe_notify(bot, request.telegram_user_id, "Ваша заявка одобрена. Отправьте /start, чтобы открыть меню.")
            text = "Заявка одобрена." if changed else "Заявка уже была обработана."
        else:
            request, changed = await services.access.reject(callback.from_user.id, request_id)
            if changed:
                await _safe_notify(bot, request.telegram_user_id, "Ваша заявка отклонена.")
            text = "Заявка отклонена." if changed else "Заявка уже была обработана."
        if callback.message:
            await safe_edit_message_text(callback.message, text, reply_markup=pending_requests_keyboard([], page=0))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:users(?::\d+)?$"))
async def admin_users(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        items = await services.users.list_users(
            callback.from_user.id,
            limit=ADMIN_PAGE_SIZE + 1,
            offset=page_offset(page, ADMIN_PAGE_SIZE),
        )
        users, has_next = split_page(items, ADMIN_PAGE_SIZE)
        key_counts = await services.users.count_keys_for_users(callback.from_user.id, [user.telegram_user_id for user in users])
        await safe_edit_message_text(
            callback.message,
            users_page_text(users, page, key_counts),
            reply_markup=users_keyboard(users, page=page, has_next=has_next),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:user:"))
async def admin_user_detail(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        actor = await require_moderator_or_admin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        user = await services.users.get_user(user_id)
        keys = await services.vpn_keys.list_for_actor(callback.from_user.id, owner_user_id=user_id, limit=10)
        stats_by_key_id = await services.traffic_stats.cached_for_keys(keys)
        has_used_trial = not await services.trial_access.can_request_trial(user_id)
        await safe_edit_message_text(
            callback.message,
            user_card_text(user, keys, stats_by_key_id, viewer_user_id=callback.from_user.id),
            reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial, actor_role=actor.role),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:userapprove:"))
async def admin_user_approve(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обрабатываю...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        await services.users.set_role(callback.from_user.id, user_id, UserRole.APPROVED_USER)
        if callback.message:
            user = await services.users.get_user(user_id)
            has_used_trial = not await services.trial_access.can_request_trial(user_id)
            await safe_edit_message_text(callback.message, "Пользователь одобрен.", reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:setmoderator:"))
async def admin_set_moderator(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обрабатываю...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        target = await services.users.get_user(user_id)
        if target.role == UserRole.MODERATOR:
            new_role = UserRole.APPROVED_USER
            result_text = "Роль модератора снята. Пользователь стал обычным одобренным пользователем."
        else:
            new_role = UserRole.MODERATOR
            result_text = "Пользователь назначен модератором."
        await services.users.set_role(callback.from_user.id, user_id, new_role)
        if callback.message:
            user = await services.users.get_user(user_id)
            has_used_trial = not await services.trial_access.can_request_trial(user_id)
            await safe_edit_message_text(callback.message, result_text, reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:block:\d+$"))
async def admin_block_user(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        actor = await require_moderator_or_admin(services, callback.from_user.id)
        user = await services.users.get_user(user_id)
        if is_blocked_user(user):
            if callback.message:
                has_used_trial = not await services.trial_access.can_request_trial(user_id)
                await safe_edit_message_text(callback.message, "Пользователь уже заблокирован.", reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial, actor_role=actor.role))
            return
        key_counts = await services.users.count_keys_for_users(callback.from_user.id, [user_id])
        if callback.message:
            await safe_edit_message_text(
                callback.message,
                block_user_confirm_text(user, key_counts.get(user_id, 0)),
                reply_markup=block_user_confirm_keyboard(user),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:block:confirm:\d+$"))
async def admin_block_user_confirm(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Блокирую...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        actor = await require_moderator_or_admin(services, callback.from_user.id)
        current = await services.users.get_user(user_id)
        if is_blocked_user(current):
            if callback.message:
                has_used_trial = not await services.trial_access.can_request_trial(user_id)
                await safe_edit_message_text(callback.message, "Пользователь уже заблокирован.", reply_markup=user_actions_keyboard(current, has_used_trial=has_used_trial, actor_role=actor.role))
            return
        result = await services.users.block_user(callback.from_user.id, user_id, revoke_active_keys=True)
        await _safe_notify(bot, user_id, "Ваш доступ был заблокирован администратором.")
        if callback.message:
            user = await services.users.get_user(user_id)
            revoked_proxy_ids = getattr(result, "revoked_proxy_ids", ())
            if result.errors:
                text = (
                    "Пользователь заблокирован в боте, но не весь серверный доступ удалось отключить автоматически.\n"
                    f"Отключено VPN-ключей: {len(result.revoked_key_ids)}\n"
                    f"Отключено прокси-доступов: {len(revoked_proxy_ids)}\n"
                    f"Ошибок: {len(result.errors)}\n"
                    "Проверьте Xray/AWG/SOCKS5/MTProto runtime и config вручную."
                )
            else:
                text = (
                    "Пользователь заблокирован.\n"
                    f"Отключено VPN-ключей: {len(result.revoked_key_ids)}\n"
                    f"Отключено прокси-доступов: {len(revoked_proxy_ids)}\n"
                    "Ошибок: 0\n"
                    "Теперь пользователю доступен только /start для повторной заявки."
                )
            has_used_trial = not await services.trial_access.can_request_trial(user_id)
            await safe_edit_message_text(callback.message, text, reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial, actor_role=actor.role))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:unblock:\d+$"))
async def admin_unblock_user(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        actor = await require_moderator_or_admin(services, callback.from_user.id)
        warning = await services.users.inspect_unblock_risk(callback.from_user.id, user_id)
        if callback.message:
            if not is_blocked_user(warning.user):
                has_used_trial = not await services.trial_access.can_request_trial(user_id)
                await safe_edit_message_text(
                    callback.message,
                    "Пользователь уже не заблокирован.",
                    reply_markup=user_actions_keyboard(warning.user, has_used_trial=has_used_trial, actor_role=actor.role),
                )
                return
            await safe_edit_message_text(
                callback.message,
                unblock_user_confirm_text(warning),
                reply_markup=unblock_user_confirm_keyboard(warning.user),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:unblock:confirm:\d+$"))
async def admin_unblock_user_confirm(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Разблокирую...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        actor = await require_moderator_or_admin(services, callback.from_user.id)
        warning = await services.users.inspect_unblock_risk(callback.from_user.id, user_id)
        has_used_trial = not await services.trial_access.can_request_trial(user_id)
        if not is_blocked_user(warning.user):
            if callback.message:
                await safe_edit_message_text(
                    callback.message,
                    "Пользователь уже не заблокирован.",
                    reply_markup=user_actions_keyboard(warning.user, has_used_trial=has_used_trial, actor_role=actor.role),
                )
            return
        user = await services.users.unblock_user(callback.from_user.id, user_id)
        if callback.message:
            await safe_edit_message_text(
                callback.message,
                unblock_user_success_text(warning),
                reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial, actor_role=actor.role),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:ukeys:\d+:\d+$"))
async def admin_user_keys(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        _, _, raw_user_id, raw_page = callback.data.split(":", 3)
        user_id = int(raw_user_id)
        page = max(int(raw_page), 0)
        keys, current_page, total_pages, has_next = await load_keys_page(
            services,
            callback.from_user.id,
            owner_user_id=user_id,
            page=page,
            page_size=ADMIN_KEYS_PAGE_SIZE,
        )
        await safe_edit_message_text(
            callback.message,
            keys_page_text(keys, current_page, viewer_user_id=callback.from_user.id, owner_user_id=user_id),
            reply_markup=keys_list_keyboard(
                keys,
                page=current_page,
                has_next=has_next,
                owner_user_id=user_id,
                total_pages=total_pages,
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:audit(?::\d+)?$"))
async def admin_audit(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        items = await services.audit.recent(actor_user_id=callback.from_user.id, limit=AUDIT_PAGE_SIZE + 1, offset=page_offset(page, AUDIT_PAGE_SIZE))
        audit_items, has_next = split_page(items, AUDIT_PAGE_SIZE)
        actor_ids = [
            int(item["actor_user_id"])  # type: ignore[call-overload]
            for item in audit_items
            if item.get("actor_user_id") is not None
        ]
        audit_users = await services.users.users.list_by_ids(actor_ids)
        rows = []
        if page > 0:
            rows.append(("Назад", f"admin:audit:{page - 1}"))
        if has_next:
            rows.append(("Дальше", f"admin:audit:{page + 1}"))
        await safe_edit_message_text(
            callback.message,
            audit_page_text(audit_items, page, audit_users),
            reply_markup=_simple_nav(rows, "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:stats(?::\d+)?$"))
async def admin_stats(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обновляю статистику...")
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        await require_superadmin(services, callback.from_user.id)
        items = await services.traffic_stats.list_for_superadmin(
            callback.from_user.id,
            limit=ADMIN_KEYS_PAGE_SIZE + 1,
            offset=page_offset(page, ADMIN_KEYS_PAGE_SIZE),
        )
        views, has_next = split_page(items, ADMIN_KEYS_PAGE_SIZE)
        rows = []
        if page > 0:
            rows.append(("Назад", f"admin:stats:{page - 1}"))
        if has_next:
            rows.append(("Дальше", f"admin:stats:{page + 1}"))
        await safe_edit_message_text(
            callback.message,
            admin_stats_page_text(views, page, viewer_user_id=callback.from_user.id),
            reply_markup=_simple_nav(rows, "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:proxy")
async def admin_proxy_status(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обновляю статус...")
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        stats = await services.proxy.lifecycle_stats(callback.from_user.id)
        status = services.proxy.service_status()
        runtime_reader = getattr(getattr(services, "mtproto", None), "runtime_status", None)
        if runtime_reader is not None:
            runtime = await runtime_reader()
            if runtime is not None:
                status = replace(
                    status,
                    mtproto_systemd_active=runtime.systemd_active,
                    mtproto_port_listening=runtime.port_listening,
                )
        await safe_edit_message_text(
            callback.message,
            proxy_admin_status_text(status, stats),
            reply_markup=_simple_nav([], "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:diagnostics")
async def admin_backend_diagnostics(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обновляю диагностику...")
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        settings = services.settings
        service_names = [
            "vpn-bot",
            settings.xray_service_name,
            f"awg-quick@{settings.awg_interface}",
        ]
        if settings.socks5_enabled:
            service_names.append(settings.socks5_service_name)
        if settings.mtproto_enabled:
            service_names.append(settings.mtproto_service_name)
        result = await run_bot_health(
            backend_health=services.backend_health,
            db=services.db,
            privilege_helpers_enabled=settings.privilege_helpers_enabled,
            service_names=service_names,
        )
        await safe_edit_message_text(
            callback.message,
            system_diagnostics_text(result),
            reply_markup=_simple_nav([], "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:proxy_stats")
async def admin_proxy_stats(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Обновляю статистику прокси...")
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        runtime = services.proxy.runtime_stats()
        runtime_status = await services.mtproto.runtime_status()
        if runtime_status is not None:
            runtime = replace(
                runtime,
                mtproto_systemd_active=runtime_status.systemd_active,
                mtproto_port_listening=runtime_status.port_listening,
            )
        runtime = replace(runtime, mtproto_runtime_secret_count=await services.mtproto.runtime_secret_count())
        stats = await services.proxy.get_admin_proxy_stats(
            callback.from_user.id,
            user_limit=ADMIN_PROXY_USER_LIMIT,
            runtime=runtime,
        )
        await safe_edit_message_text(
            callback.message,
            admin_proxy_stats_text(stats),
            reply_markup=_simple_nav([], "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:issue")
async def admin_issue_choose_user(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        items = await services.users.list_users(callback.from_user.id, limit=ADMIN_PAGE_SIZE + 1)
        users, has_next = split_page(items, ADMIN_PAGE_SIZE)
        await safe_edit_message_text(
            callback.message,
            "Выберите пользователя для выдачи ключа:",
            reply_markup=admin_issue_users_keyboard(users, page=0, has_next=has_next),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:issuepage:\d+$"))
async def admin_issue_choose_user_page(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    page = _page_from_callback(callback.data)
    try:
        await require_superadmin(services, callback.from_user.id)
        items = await services.users.list_users(
            callback.from_user.id,
            limit=ADMIN_PAGE_SIZE + 1,
            offset=page_offset(page, ADMIN_PAGE_SIZE),
        )
        users, has_next = split_page(items, ADMIN_PAGE_SIZE)
        await safe_edit_message_text(
            callback.message,
            "Выберите пользователя для выдачи ключа:",
            reply_markup=admin_issue_users_keyboard(users, page=page, has_next=has_next),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:issue:\d+$"))
async def admin_issue_user_selected(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        user = await services.users.get_user(user_id)
        if is_blocked_user(user):
            from services.errors import AccessDenied
            raise AccessDenied("Нельзя выдать ключ заблокированному пользователю")
        owner_is_pending = user.role == UserRole.PENDING_USER
        await state.set_state(AdminCreateKeyStates.choosing_type)
        await state.update_data(owner_user_id=user.telegram_user_id, owner_is_pending=owner_is_pending)
        text = f"{user_card_text(user)}\n\n{ONE_KEY_ONE_DEVICE_WARNING}\n\nВыберите тип ключа:"
        await safe_edit_message_text(callback.message, text, reply_markup=admin_key_type_keyboard(user.telegram_user_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(AdminCreateKeyStates.choosing_type, F.data.regexp(r"^admin:ctype:(xray|awg):\d+$"))
async def admin_issue_type_selected(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        _, _, key_type, raw_user_id = callback.data.split(":", 3)
        owner_user_id = int(raw_user_id)
        data = await state.get_data()
        expected_owner_id = data.get("owner_user_id")
        if expected_owner_id is None or int(expected_owner_id) != owner_user_id:
            await state.clear()
            await safe_callback_answer(callback, "Действие устарело, начните выдачу заново", show_alert=True)
            await safe_edit_message_text(
                callback.message,
                "Действие устарело, начните выдачу заново.",
                reply_markup=admin_panel_keyboard(),
            )
            return
        await safe_callback_answer(callback)
        await state.set_state(AdminCreateKeyStates.waiting_note)
        await state.update_data(owner_user_id=owner_user_id, key_type=key_type)
        await safe_edit_message_text(
            callback.message,
            f"{NOTE_CREATE_WARNING}\n\nВведите заметку для ключа или отправьте <code>-</code>, чтобы оставить пустой.",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminCreateKeyStates.waiting_note)
async def admin_issue_note(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        note = _clean_note(message.text)
        data = await state.get_data()
        key_type = str(data.get("key_type") or "")
        await state.update_data(note=note)
        if key_type == VpnKeyType.AWG.value:
            await state.set_state(AdminCreateKeyStates.waiting_mtu)
            await message.answer("Выберите MTU для ключа:", reply_markup=mtu_choice_keyboard())
        else:
            await state.set_state(AdminCreateKeyStates.waiting_expiry)
            await message.answer("Выберите срок действия ключа:", reply_markup=expiry_choice_keyboard())
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminCreateKeyStates.waiting_mtu, F.data.regexp(r"^mtu:\d+$"))
async def admin_issue_mtu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        raw = callback.data.split(":", 1)[1]
        mtu = int(raw)
        if mtu < 1 or mtu > 1500:
            await safe_callback_answer(callback, "Недопустимое значение MTU: 1–1500", show_alert=True)
            return
        await state.update_data(mtu=mtu)
        await state.set_state(AdminCreateKeyStates.waiting_expiry)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            "Выберите срок действия ключа:",
            reply_markup=expiry_choice_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(AdminCreateKeyStates.waiting_mtu, F.data == "mtu:custom")
async def admin_issue_mtu_custom_request(callback: CallbackQuery, state: FSMContext) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.message is None:
        return
    await safe_callback_answer(callback)
    await state.set_state(AdminCreateKeyStates.waiting_mtu_custom)
    await safe_edit_message_text(callback.message, "Введите MTU (от 1 до 1500):", reply_markup=None)


@router.message(AdminCreateKeyStates.waiting_mtu_custom)
async def admin_issue_mtu_custom(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        mtu = _parse_mtu(message.text or "")
        if mtu is None:
            await message.answer("Введите целое число от 1 до 1500:")
            return
        await state.update_data(mtu=mtu)
        await state.set_state(AdminCreateKeyStates.waiting_expiry)
        await message.answer("Выберите срок действия ключа:", reply_markup=expiry_choice_keyboard())
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminCreateKeyStates.waiting_expiry, F.data.regexp(r"^expiry:(permanent|\d+)$"))
async def admin_issue_expiry(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        raw = callback.data.split(":", 1)[1]
        if raw == "permanent":
            expires_at = None
        else:
            days = int(raw)
            if days < 1 or days > services.settings.key_max_trial_days:
                await safe_callback_answer(callback, f"Недопустимый срок: 1–{services.settings.key_max_trial_days} дней", show_alert=True)
                return
            from datetime import datetime, timedelta, timezone
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()
        await state.update_data(expires_at=expires_at)
        data = await state.get_data()
        owner_user_id = int(data["owner_user_id"])
        owner = await services.users.get_user(owner_user_id)
        key_type = str(data["key_type"])
        note = data.get("note")
        mtu = int(data["mtu"]) if data.get("mtu") is not None else None
        await state.set_state(AdminCreateKeyStates.confirming)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            create_confirm_text(key_type, note, owner=owner, expires_at=expires_at, mtu=mtu),
            reply_markup=confirm_cancel_keyboard("admin:cconfirm"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(AdminCreateKeyStates.waiting_expiry, F.data == "expiry:custom")
async def admin_issue_expiry_custom(callback: CallbackQuery, state: FSMContext) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.message is None:
        return
    await safe_callback_answer(callback)
    await state.set_state(AdminCreateKeyStates.waiting_custom_days)
    await safe_edit_message_text(
        callback.message,
        "Введите количество дней (от 1 до 365):",
        reply_markup=None,
    )


@router.message(AdminCreateKeyStates.waiting_custom_days)
async def admin_issue_custom_days(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        text = (message.text or "").strip()
        if not text.isdigit():
            await message.answer("Введите целое число дней (от 1 до 365):")
            return
        days = int(text)
        max_days = services.settings.key_max_trial_days
        if days < 1 or days > max_days:
            await message.answer(f"Введите число от 1 до {max_days}:")
            return
        from datetime import datetime, timedelta, timezone
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()
        await state.update_data(expires_at=expires_at)
        data = await state.get_data()
        owner_user_id = int(data["owner_user_id"])
        owner = await services.users.get_user(owner_user_id)
        key_type = str(data["key_type"])
        note = data.get("note")
        mtu = int(data["mtu"]) if data.get("mtu") is not None else None
        await state.set_state(AdminCreateKeyStates.confirming)
        await message.answer(
            create_confirm_text(key_type, note, owner=owner, expires_at=expires_at, mtu=mtu),
            reply_markup=confirm_cancel_keyboard("admin:cconfirm"),
        )
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminCreateKeyStates.confirming, F.data == "admin:cconfirm")
async def admin_issue_confirm(callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter, bot: Bot) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    data = await state.get_data()
    try:
        owner_user_id = int(data["owner_user_id"])
        key_type = str(data["key_type"])
        note = data.get("note")
        expires_at: str | None = data.get("expires_at")
        mtu = int(data["mtu"]) if data.get("mtu") is not None else None
        owner_is_pending = bool(data.get("owner_is_pending", False))
        owner = await services.users.get_user(owner_user_id)
        await require_superadmin(services, callback.from_user.id)
        profile = TelegramUserProfile(owner.telegram_user_id, owner.username, owner.first_name)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        await state.clear()
        await safe_callback_answer(callback, "Создаю ключ...")
        if key_type == VpnKeyType.XRAY.value:
            result = await services.xray.create_xray_key(
                callback.from_user.id, profile, note,
                expires_at=expires_at,
                allow_pending_owner=owner_is_pending,
            )
        elif key_type == VpnKeyType.AWG.value:
            result = await services.awg.create_awg_key(
                callback.from_user.id, profile, note,
                expires_at=expires_at,
                allow_pending_owner=owner_is_pending,
                mtu=mtu,
            )
        else:
            await safe_edit_message_text(callback.message, "Неизвестный тип ключа.")
            return
        await safe_edit_message_text(
            callback.message,
            result.config_text,
            reply_markup=key_actions_keyboard(result.key, owner_user_id=result.key.owner_user_id),
        )
        plain_awg_config: str | None = None
        if result.key.key_type == VpnKeyType.AWG:
            plain_awg_config = await services.awg.get_awg_client_config_plain(callback.from_user.id, result.key.id, audit=False)
            filename = awg_config_filename(result.key)
            await callback.message.answer_document(BufferedInputFile(plain_awg_config.encode("utf-8"), filename=filename))
        if owner_is_pending:
            await _deliver_key_to_pending_user(bot, result, owner_user_id, plain_awg_config=plain_awg_config)
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _deliver_key_to_pending_user(bot: Bot, result: Any, user_id: int, plain_awg_config: str | None = None) -> None:
    try:
        if result.key.key_type == VpnKeyType.AWG:
            await bot.send_message(
                user_id,
                f"Администратор выдал вам AWG-ключ #{result.key.id}.\n\n{result.config_text}",
            )
            if plain_awg_config is not None:
                from bot.messages import awg_config_filename
                filename = awg_config_filename(result.key)
                await bot.send_document(
                    user_id,
                    document=BufferedInputFile(plain_awg_config.encode("utf-8"), filename=filename),
                )
        else:
            await bot.send_message(
                user_id,
                f"Администратор выдал вам Xray-ключ #{result.key.id}.\n\n{result.config_text}",
            )
    except Exception:
        logger.warning("Не удалось доставить ключ PENDING-пользователю %s", user_id, exc_info=True)


@router.callback_query(F.data.regexp(r"^admin:trial(?::\d+)?$"))
async def admin_trial_list(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        await require_superadmin(services, callback.from_user.id)
        items = await services.trial_access.list_pending_requests(
            limit=ADMIN_PAGE_SIZE + 1,
            offset=page_offset(page, ADMIN_PAGE_SIZE),
        )
        requests, has_next = split_page(items, ADMIN_PAGE_SIZE)
        if not requests:
            await safe_edit_message_text(
                callback.message,
                "Нет ожидающих заявок на пробный доступ.",
                reply_markup=_simple_nav([], "admin:panel"),
            )
            return
        lines = ["<b>Заявки на пробный доступ:</b>"]
        for req in requests:
            lines.append(f"#{req.id} — tg{req.telegram_user_id} ({req.key_type.value.upper()})")
        nav_rows: list[tuple[str, str]] = []
        if page > 0:
            nav_rows.append(("Назад", f"admin:trial:{page - 1}"))
        if has_next:
            nav_rows.append(("Дальше", f"admin:trial:{page + 1}"))
        from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
        keyboard: list[list[InlineKeyboardButton]] = []
        for req in requests:
            keyboard.append([
                InlineKeyboardButton(text=f"Одобрить #{req.id}", callback_data=f"admin:trial:approve:{req.id}"),
                InlineKeyboardButton(text=f"Отклонить #{req.id}", callback_data=f"admin:trial:reject:{req.id}"),
            ])
        if nav_rows:
            keyboard.append([InlineKeyboardButton(text=text, callback_data=data) for text, data in nav_rows])
        keyboard.append([InlineKeyboardButton(text="Назад", callback_data="admin:panel")])
        await safe_edit_message_text(
            callback.message,
            "\n".join(lines),
            reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:trial:approve:\d+$"))
async def admin_trial_approve(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        request_id = int(callback.data.rsplit(":", 1)[-1])
        await safe_callback_answer(callback, "Обрабатываю...")
        await services.trial_access.approve_trial_request(callback.from_user.id, request_id)
        await safe_edit_message_text(
            callback.message,
            "Пробный ключ выдан. Конфиг отправлен пользователю.",
            reply_markup=_simple_nav([], "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:trial:reject:\d+$"))
async def admin_trial_reject(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        request_id = int(callback.data.rsplit(":", 1)[-1])
        await safe_callback_answer(callback, "Отклоняю...")
        await services.trial_access.reject_trial_request(callback.from_user.id, request_id)
        await safe_edit_message_text(
            callback.message,
            "Заявка на пробный доступ отклонена.",
            reply_markup=_simple_nav([], "admin:panel"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:trial:reset:\d+$"))
async def admin_trial_reset(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        await safe_callback_answer(callback, "Сбрасываю квоту...")
        await services.trial_access.admin_reset_trial_quota(callback.from_user.id, user_id)
        user = await services.users.get_user(user_id)
        await safe_edit_message_text(
            callback.message,
            "Квота пробных доступов сброшена.",
            reply_markup=user_actions_keyboard(user, has_used_trial=False),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:unote:\d+$"))
async def admin_edit_user_note(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        user = await services.users.get_user(user_id)
        await state.set_state(AdminEditUserNoteStates.waiting_note)
        await state.update_data(target_user_id=user_id)
        current = f" Текущая: <code>{user.note}</code>" if user.note else ""
        await safe_edit_message_text(
            callback.message,
            f"Введите заметку для пользователя <code>{user_id}</code> или отправьте <code>-</code>, чтобы очистить.{current}",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminEditUserNoteStates.waiting_note)
async def admin_edit_user_note_input(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        data = await state.get_data()
        user_id = int(data["target_user_id"])
        await services.notes.update_user_note(message.from_user.id, user_id, message.text)
        await state.clear()
        user = await services.users.get_user(user_id)
        keys = await services.vpn_keys.list_for_actor(message.from_user.id, owner_user_id=user_id, limit=10)
        stats_by_key_id = await services.traffic_stats.cached_for_keys(keys)
        has_used_trial = not await services.trial_access.can_request_trial(user_id)
        await message.answer(
            user_card_text(user, keys, stats_by_key_id, viewer_user_id=message.from_user.id),
            reply_markup=user_actions_keyboard(user, has_used_trial=has_used_trial),
        )
    except ValueError as exc:
        await answer_message_error(message, exc)
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(F.data == "admin:backup")
async def admin_backup_now(callback: CallbackQuery, services: Services, bot: Bot) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if not services.offsite_backup.enabled:
            await safe_callback_answer(
                callback,
                "OFFSITE_BACKUP_ENCRYPTION_KEY не настроен — бэкап отключён.",
                show_alert=True,
            )
            return
        await safe_callback_answer(callback, "Создаю бэкап...")
        result = await services.offsite_backup.send_to_admins(bot, services.settings.admin_ids)
        text = (
            "Бэкап отправлен.\n"
            f"Успешно: {result['success']}\n"
            f"Ошибок: {result['failed']}"
        )
        await safe_edit_message_text(callback.message, text, reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _safe_notify(bot: Bot, user_id: int, text: str) -> None:
    try:
        await bot.send_message(user_id, text)
    except Exception:
        logger.warning("Не удалось уведомить пользователя %s", user_id, exc_info=True)


def _page_from_callback(data: str | None) -> int:
    if not data:
        return 0
    last = data.split(":")[-1]
    return max(int(last), 0) if last.isdigit() else 0


def _clean_note(value: str | None) -> str | None:
    if value is None:
        return None
    note = value.strip()
    return None if note in {"", "-"} else note


def _parse_schedule_time(text: str) -> str | None:
    """Parse "DD.MM.YYYY HH:MM" Moscow time (UTC+3) to UTC ISO string. Returns None if invalid or in the past."""
    from datetime import datetime, timezone, timedelta
    text = text.strip()
    try:
        dt_msk = datetime.strptime(text, "%d.%m.%Y %H:%M")
    except ValueError:
        return None
    msk_tz = timezone(timedelta(hours=3))
    dt_utc = dt_msk.replace(tzinfo=msk_tz).astimezone(timezone.utc)
    if dt_utc <= datetime.now(timezone.utc):
        return None
    return dt_utc.replace(microsecond=0).isoformat()


def _parse_mtu(text: str) -> int | None:
    text = text.strip()
    if not text.isdigit():
        return None
    value = int(text)
    return value if 1 <= value <= 1500 else None


async def _show_announcement_batches(callback: CallbackQuery, services: Services, *, prefix: str | None = None) -> None:
    if callback.from_user is None or callback.message is None:
        return
    batches = await services.announcements.list_incomplete_batches(callback.from_user.id, limit=10)
    text = announcement_batches_text(batches)
    if prefix:
        text = f"{prefix}\n\n{text}"
    await safe_edit_message_text(
        callback.message,
        text,
        reply_markup=announcement_batches_keyboard(batches),
    )


def _simple_nav(rows: list[tuple[str, str]], back_data: str) -> InlineKeyboardMarkup:
    from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

    keyboard = []
    if rows:
        keyboard.append([InlineKeyboardButton(text=text, callback_data=data) for text, data in rows])
    keyboard.append([InlineKeyboardButton(text="Назад", callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)
