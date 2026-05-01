from __future__ import annotations

import logging
from typing import Any

from aiogram import Bot, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import (
    NOTE_CREATE_WARNING,
    ONE_KEY_ONE_DEVICE_WARNING,
    access_request_text,
    access_request_decision_confirm_text,
    access_requests_page_text,
    admin_stats_page_text,
    audit_page_text,
    block_user_confirm_text,
    create_confirm_text,
    keys_page_text,
    unblock_user_confirm_text,
    unblock_user_success_text,
    user_card_text,
    users_page_text,
)
from bot.fsm.states import AdminCreateKeyStates
from bot.fsm.states import AdminAnnouncementStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.admin import (
    admin_issue_users_keyboard,
    admin_key_type_keyboard,
    admin_panel_keyboard,
    announcement_confirm_keyboard,
    access_request_decision_confirm_keyboard,
    block_user_confirm_keyboard,
    pending_requests_keyboard,
    unblock_user_confirm_keyboard,
    user_actions_keyboard,
    users_keyboard,
)
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.keys import key_actions_keyboard, keys_list_keyboard
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


@router.message(Command("admin"))
async def admin_command(message: Message, services: Any) -> None:
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
async def admin_menu_message(message: Message, services: Any) -> None:
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
async def admin_panel(callback: CallbackQuery, services: Any) -> None:
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


@router.callback_query(F.data == "admin:announce")
async def admin_announcement_start(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
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
async def admin_announcement_message(message: Message, state: FSMContext, services: Any) -> None:
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
    services: Any,
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


@router.callback_query(AdminAnnouncementStates.confirming, F.data == "admin:announce:cancel")
async def admin_announcement_cancel(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
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


@router.callback_query(F.data.regexp(r"^admin:reqs(?::\d+)?$"))
async def admin_requests(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
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
async def admin_request_detail(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        request_id = int(callback.data.rsplit(":", 1)[-1])
        request = await services.access.get_request(callback.from_user.id, request_id)
        await safe_edit_message_text(callback.message, access_request_text(request), reply_markup=pending_requests_keyboard([request]))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:approve:\d+$"))
async def admin_approve(callback: CallbackQuery, services: Any, bot: Bot) -> None:
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
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=admin_panel_keyboard())
                return
            await safe_edit_message_text(
                callback.message,
                access_request_decision_confirm_text(request, "approve"),
                reply_markup=access_request_decision_confirm_keyboard(request.id, "approve"),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:reject:\d+$"))
async def admin_reject(callback: CallbackQuery, services: Any, bot: Bot) -> None:
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
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=admin_panel_keyboard())
                return
            await safe_edit_message_text(
                callback.message,
                access_request_decision_confirm_text(request, "reject"),
                reply_markup=access_request_decision_confirm_keyboard(request.id, "reject"),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:(approve|reject):confirm:\d+$"))
async def admin_access_decision_confirm(callback: CallbackQuery, services: Any, bot: Bot) -> None:
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
                await safe_edit_message_text(callback.message, "Заявка уже была обработана.", reply_markup=admin_panel_keyboard())
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
            await safe_edit_message_text(callback.message, text, reply_markup=admin_panel_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:users(?::\d+)?$"))
async def admin_users(callback: CallbackQuery, services: Any) -> None:
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
async def admin_user_detail(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        user = await services.users.get_user(user_id)
        keys = await services.vpn_keys.list_for_actor(callback.from_user.id, owner_user_id=user_id, limit=10)
        stats_by_key_id = await services.traffic_stats.cached_for_keys(keys)
        await safe_edit_message_text(
            callback.message,
            user_card_text(user, keys, stats_by_key_id, viewer_user_id=callback.from_user.id),
            reply_markup=user_actions_keyboard(user),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:userapprove:"))
async def admin_user_approve(callback: CallbackQuery, services: Any) -> None:
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
            await safe_edit_message_text(callback.message, "Пользователь одобрен.", reply_markup=user_actions_keyboard(user))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:block:\d+$"))
async def admin_block_user(callback: CallbackQuery, services: Any) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        await require_superadmin(services, callback.from_user.id)
        user = await services.users.get_user(user_id)
        if is_blocked_user(user):
            if callback.message:
                await safe_edit_message_text(callback.message, "Пользователь уже заблокирован.", reply_markup=user_actions_keyboard(user))
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
async def admin_block_user_confirm(callback: CallbackQuery, services: Any) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Блокирую...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        await require_superadmin(services, callback.from_user.id)
        current = await services.users.get_user(user_id)
        if is_blocked_user(current):
            if callback.message:
                await safe_edit_message_text(callback.message, "Пользователь уже заблокирован.", reply_markup=user_actions_keyboard(current))
            return
        result = await services.users.block_user(callback.from_user.id, user_id, revoke_active_keys=True)
        if callback.message:
            user = await services.users.get_user(user_id)
            if result.errors:
                text = (
                    "Пользователь заблокирован в боте, но не все VPN-ключи удалось отключить автоматически.\n"
                    f"Отключено ключей: {len(result.revoked_key_ids)}\n"
                    f"Ошибок: {len(result.errors)}\n"
                    "Проверьте Xray/AWG runtime и config вручную."
                )
            else:
                text = (
                    "Пользователь заблокирован.\n"
                    f"Отключено ключей: {len(result.revoked_key_ids)}\n"
                    "Ошибок: 0\n"
                    "Теперь пользователю доступен только /start для повторной заявки."
                )
            await safe_edit_message_text(callback.message, text, reply_markup=user_actions_keyboard(user))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:unblock:\d+$"))
async def admin_unblock_user(callback: CallbackQuery, services: Any) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        warning = await services.users.inspect_unblock_risk(callback.from_user.id, user_id)
        if callback.message:
            if not is_blocked_user(warning.user):
                await safe_edit_message_text(
                    callback.message,
                    "Пользователь уже не заблокирован.",
                    reply_markup=user_actions_keyboard(warning.user),
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
async def admin_unblock_user_confirm(callback: CallbackQuery, services: Any) -> None:
    if callback.from_user is None or callback.data is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback, "Разблокирую...")
    try:
        user_id = int(callback.data.rsplit(":", 1)[-1])
        warning = await services.users.inspect_unblock_risk(callback.from_user.id, user_id)
        if not is_blocked_user(warning.user):
            if callback.message:
                await safe_edit_message_text(
                    callback.message,
                    "Пользователь уже не заблокирован.",
                    reply_markup=user_actions_keyboard(warning.user),
                )
            return
        user = await services.users.unblock_user(callback.from_user.id, user_id)
        if callback.message:
            await safe_edit_message_text(
                callback.message,
                unblock_user_success_text(warning),
                reply_markup=user_actions_keyboard(user),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:ukeys:\d+:\d+$"))
async def admin_user_keys(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        _, _, raw_user_id, raw_page = callback.data.split(":", 3)
        user_id = int(raw_user_id)
        page = max(int(raw_page), 0)
        total_count = await services.vpn_keys.count_for_actor(callback.from_user.id, owner_user_id=user_id)
        total_pages = max(1, (total_count + ADMIN_KEYS_PAGE_SIZE - 1) // ADMIN_KEYS_PAGE_SIZE)
        current_page = min(page, total_pages - 1)
        keys = await services.vpn_keys.list_for_actor(
            callback.from_user.id,
            owner_user_id=user_id,
            limit=ADMIN_KEYS_PAGE_SIZE,
            offset=page_offset(current_page, ADMIN_KEYS_PAGE_SIZE),
        )
        if not keys and current_page > 0:
            total_count = await services.vpn_keys.count_for_actor(callback.from_user.id, owner_user_id=user_id)
            total_pages = max(1, (total_count + ADMIN_KEYS_PAGE_SIZE - 1) // ADMIN_KEYS_PAGE_SIZE)
            current_page = max(0, min(current_page - 1, total_pages - 1))
            keys = await services.vpn_keys.list_for_actor(
                callback.from_user.id,
                owner_user_id=user_id,
                limit=ADMIN_KEYS_PAGE_SIZE,
                offset=page_offset(current_page, ADMIN_KEYS_PAGE_SIZE),
            )
        has_next = current_page + 1 < total_pages
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
async def admin_audit(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data)
    try:
        await require_superadmin(services, callback.from_user.id)
        items = await services.audit.recent(limit=AUDIT_PAGE_SIZE + 1, offset=page_offset(page, AUDIT_PAGE_SIZE))
        audit_items, has_next = split_page(items, AUDIT_PAGE_SIZE)
        actor_ids = [
            int(item["actor_user_id"])
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
async def admin_stats(callback: CallbackQuery, services: Any) -> None:
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


@router.callback_query(F.data == "admin:issue")
async def admin_issue_choose_user(callback: CallbackQuery, services: Any) -> None:
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
async def admin_issue_choose_user_page(callback: CallbackQuery, services: Any) -> None:
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
async def admin_issue_user_selected(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        user_id = int(callback.data.rsplit(":", 1)[-1])
        user = await services.users.get_user(user_id)
        await state.set_state(AdminCreateKeyStates.choosing_type)
        await state.update_data(owner_user_id=user.telegram_user_id)
        text = f"{user_card_text(user)}\n\n{ONE_KEY_ONE_DEVICE_WARNING}\n\nВыберите тип ключа:"
        await safe_edit_message_text(callback.message, text, reply_markup=admin_key_type_keyboard(user.telegram_user_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(AdminCreateKeyStates.choosing_type, F.data.regexp(r"^admin:ctype:(xray|awg):\d+$"))
async def admin_issue_type_selected(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
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
async def admin_issue_note(message: Message, state: FSMContext, services: Any) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message, ADMIN_PRIVATE_ONLY_TEXT):
        return
    data = await state.get_data()
    try:
        owner_user_id = int(data["owner_user_id"])
        owner = await services.users.get_user(owner_user_id)
        key_type = str(data["key_type"])
        note = _clean_note(message.text)
        await state.update_data(note=note)
        await state.set_state(AdminCreateKeyStates.confirming)
        await message.answer(create_confirm_text(key_type, note, owner=owner), reply_markup=confirm_cancel_keyboard("admin:cconfirm"))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(AdminCreateKeyStates.confirming, F.data == "admin:cconfirm")
async def admin_issue_confirm(callback: CallbackQuery, state: FSMContext, services: Any, rate_limiter: RateLimiter) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT):
        return
    data = await state.get_data()
    try:
        owner_user_id = int(data["owner_user_id"])
        key_type = str(data["key_type"])
        note = data.get("note")
        owner = await services.users.get_user(owner_user_id)
        profile = TelegramUserProfile(owner.telegram_user_id, owner.username, owner.first_name)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        await state.clear()
        await safe_callback_answer(callback, "Создаю ключ...")
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
                filename=awg_config_filename(result.key),
                reply_markup=key_actions_keyboard(result.key, owner_user_id=result.key.owner_user_id),
                edit_text=True,
            )
        else:
            await safe_edit_message_text(
                callback.message,
                result.config_text,
                reply_markup=key_actions_keyboard(result.key, owner_user_id=result.key.owner_user_id),
            )
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


def _simple_nav(rows: list[tuple[str, str]], back_data: str):
    from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

    keyboard = []
    if rows:
        keyboard.append([InlineKeyboardButton(text=text, callback_data=data) for text, data in rows])
    keyboard.append([InlineKeyboardButton(text="Назад", callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)
